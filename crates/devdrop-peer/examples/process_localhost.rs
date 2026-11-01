//! Native process/loopback fault evidence, not cross-device or VM evidence.
//! Only this coordinator's marked disposable roots and fixed selected bytes exist.
use devdrop_core::file_permissions as access;
use devdrop_peer::{
    pairing::{Paired, PairingFlow, PairingOffer, Scope},
    store::Inbox,
    transport::{PeerClient, PeerServer},
    wire::{Change, Envelope, Receipt, ReceiptStatus, ZERO_DIGEST},
    PeerError, PeerResult,
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Component, Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};

const CONTROL_LIMIT: usize = 64 * 1024;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(7);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(40);
const MARKER: &str = "run-marker.json";
const MARKER_SCHEMA: &str = "devdrop-process-localhost-scratch/v1";
const FIXTURE_PATH: &str = "src/shared.txt";
const FIXTURE_BYTES: &[u8] = b"generated real peer process fixture\n";
fn err(message: &'static str) -> PeerError {
    PeerError(message)
}
fn require(value: bool, message: &'static str) -> PeerResult<()> {
    if value {
        Ok(())
    } else {
        Err(err(message))
    }
}
fn io<T>(value: std::io::Result<T>) -> PeerResult<T> {
    value.map_err(|_| err("Disposable process fixture IO failed."))
}
fn hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
fn hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn scope() -> Scope {
    Scope {
        channel: "disposable-process-fixture".into(),
        paths: BTreeSet::from([FIXTURE_PATH.into()]),
        allow_delete: false,
        max_messages: 2,
        max_bytes_per_proposal: 32 * 1024,
        max_total_bytes: 64 * 1024,
    }
}
fn permissions() -> access::FilePermissions {
    #[cfg(unix)]
    {
        access::FilePermissions::Unix { mode: 0o600 }
    }
    #[cfg(windows)]
    {
        access::FilePermissions::Windows { readonly: false }
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Role {
    Sender,
    Receiver,
}
impl Role {
    fn name(self) -> &'static str {
        match self {
            Self::Sender => "sender",
            Self::Receiver => "receiver",
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    schema: String,
    nonce: String,
    coordinator_pid: u32,
    role: Role,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Init {
    root: PathBuf,
    nonce: String,
    coordinator_pid: u32,
    role: Role,
    reopen: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Control {
    Init {
        init: Init,
    },
    Pair {
        remote: PairingOffer,
        confirmed_fingerprint: String,
        scope: Scope,
    },
    Listen {},
    Arm {},
    Wait {},
    Send {
        address: SocketAddr,
        retry_only: bool,
    },
    Status {},
    Review {
        pairing_id: String,
        sequence: u64,
        digest: String,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case", deny_unknown_fields)]
enum Reply {
    Hello {
        pid: u32,
        offer: PairingOffer,
    },
    Paired {
        pairing_id: String,
    },
    Listening {
        address: SocketAddr,
    },
    Armed {},
    Served {
        ok: bool,
    },
    Sent {
        ok: bool,
        failure_class: Option<String>,
        receipt: Option<Receipt>,
    },
    Status {
        pending: u32,
        paired: bool,
        has_outbox: bool,
        workspace_absent: bool,
    },
    Reviewed {
        digest: String,
        payload_hash: String,
        changes: u32,
    },
    Failure {},
}
fn read_line_bounded(reader: &mut impl BufRead) -> PeerResult<Vec<u8>> {
    let mut output = Vec::new();
    loop {
        let bytes = io(reader.fill_buf())?;
        if bytes.is_empty() {
            return Err(err("Worker control pipe closed."));
        }
        let end = bytes
            .iter()
            .position(|b| *b == b'\n')
            .map(|index| index + 1);
        let count = end.unwrap_or(bytes.len());
        require(
            output.len() + count <= CONTROL_LIMIT,
            "Worker control frame exceeded its limit.",
        )?;
        output.extend_from_slice(&bytes[..count]);
        reader.consume(count);
        if end.is_some() {
            return Ok(output);
        }
    }
}
fn read_json<T: serde::de::DeserializeOwned>(reader: &mut impl BufRead) -> PeerResult<T> {
    serde_json::from_slice(&read_line_bounded(reader)?)
        .map_err(|_| err("Worker control schema is invalid."))
}
fn write_json(writer: &mut impl Write, value: &impl Serialize) -> PeerResult<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| err("Worker control encoding failed."))?;
    require(
        bytes.len() < CONTROL_LIMIT,
        "Worker control frame exceeded its limit.",
    )?;
    io(writer.write_all(&bytes))?;
    io(writer.write_all(b"\n"))?;
    io(writer.flush())
}
fn no_symlinks(path: &Path) -> PeerResult<()> {
    require(
        path.is_absolute(),
        "Scratch path must be canonical and absolute.",
    )?;
    let mut partial = PathBuf::new();
    for component in path.components() {
        require(
            !matches!(component, Component::ParentDir | Component::CurDir),
            "Scratch traversal is refused.",
        )?;
        partial.push(component);
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        let metadata = io(fs::symlink_metadata(&partial))?;
        require(
            !metadata.file_type().is_symlink(),
            "Scratch symlinks are refused.",
        )?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            require(
                metadata.file_attributes() & 0x400 == 0,
                "Scratch reparses are refused.",
            )?;
        }
    }
    Ok(())
}
fn private_dir(path: &Path) -> PeerResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        io(fs::DirBuilder::new().mode(0o700).create(path))?;
    }
    #[cfg(windows)]
    {
        io(fs::create_dir(path))?;
        access::make_disposable_test_directory_private(path).map_err(err)?;
    }
    Ok(())
}
fn directory_file(path: &Path) -> PeerResult<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x02000000 | 0x00200000);
    }
    io(options.open(path))
}
fn validate_init(init: &Init) -> PeerResult<PathBuf> {
    require(
        hex(&init.nonce) && init.coordinator_pid > 0,
        "Invalid fixture coordinator marker.",
    )?;
    no_symlinks(&init.root)?;
    let canonical = io(fs::canonicalize(&init.root))?;
    require(
        canonical == init.root,
        "Scratch root must already be canonical.",
    )?;
    require(
        canonical.file_name().and_then(|s| s.to_str()) == Some(init.role.name()),
        "Scratch role namespace mismatch.",
    )?;
    let parent = canonical
        .parent()
        .ok_or(err("Missing generated scratch parent."))?;
    require(
        parent
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.starts_with("devdrop-process-localhost-") && s.len() <= 80),
        "Scratch root is outside the generated fixture namespace.",
    )?;
    access::inspect_directory(&directory_file(&canonical)?).map_err(err)?;
    let marker_path = canonical.join(MARKER);
    let metadata = io(fs::symlink_metadata(&marker_path))?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= 2048,
        "Invalid generated scratch marker type or size.",
    )?;
    let marker: Marker = serde_json::from_slice(&io(fs::read(marker_path))?)
        .map_err(|_| err("Invalid generated scratch marker."))?;
    require(
        marker.schema == MARKER_SCHEMA
            && marker.nonce == init.nonce
            && marker.coordinator_pid == init.coordinator_pid
            && marker.role == init.role,
        "Scratch marker does not match the trusted fixture coordinator.",
    )?;
    let mut count = 0;
    for entry in io(fs::read_dir(&canonical))? {
        count += 1;
        require(count <= 2, "Unexpected scratch layout.")?;
        let entry = io(entry)?;
        let name = entry.file_name();
        let allowed =
            name == MARKER || (init.role == Role::Receiver && init.reopen && name == "queue");
        require(allowed, "Unexpected file in disposable scratch root.")?;
    }
    require(
        init.role == Role::Receiver || !init.reopen,
        "Sender identities/outboxes cannot be reopened.",
    )?;
    Ok(canonical)
}
fn failure_class(error: &PeerError) -> String {
    if error.0 == "Mutual TLS server authentication failed." {
        "server_tls"
    } else if error.0.contains("pin") {
        "certificate_pin"
    } else {
        "request_failed"
    }
    .into()
}
async fn worker() -> PeerResult<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut input = BufReader::new(stdin.lock());
    let mut output = stdout.lock();
    let Control::Init { init } = read_json(&mut input)? else {
        return Err(err("Worker initialization is required."));
    };
    let root = validate_init(&init)?;
    let mut flow = Some(PairingFlow::new_ephemeral()?);
    let offer = flow
        .as_ref()
        .ok_or(err("Missing ephemeral identity."))?
        .offer();
    let inbox = if init.role == Role::Receiver {
        Some(Arc::new(Mutex::new(if init.reopen {
            Inbox::open(&root.join("queue"))?
        } else {
            Inbox::create_new(&root.join("queue"))?
        })))
    } else {
        None
    };
    let mut pair: Option<Paired> = None;
    let mut server: Option<Arc<PeerServer>> = None;
    let mut served: Option<JoinHandle<PeerResult<Receipt>>> = None;
    let mut outbox: Option<Envelope> = None;
    write_json(
        &mut output,
        &Reply::Hello {
            pid: std::process::id(),
            offer,
        },
    )?;
    loop {
        let command: Control = read_json(&mut input)?;
        let reply: PeerResult<Reply> = async {
            match command {
                Control::Pair {
                    remote,
                    confirmed_fingerprint,
                    scope: approved,
                } => {
                    require(
                        pair.is_none() && approved == scope(),
                        "Only the exact disposable scope can be paired once.",
                    )?;
                    let approved_pair = flow
                        .take()
                        .ok_or(err("Ephemeral offer already consumed."))?
                        .approve(&remote, &confirmed_fingerprint, approved)?;
                    let pairing_id = approved_pair.id().to_owned();
                    pair = Some(approved_pair);
                    Ok(Reply::Paired { pairing_id })
                }
                Control::Listen {} => {
                    require(
                        init.role == Role::Receiver && server.is_none(),
                        "Receiver listener already exists or role is invalid.",
                    )?;
                    let peer = Arc::new(
                        PeerServer::bind(
                            pair.as_ref()
                                .ok_or(err("Explicit pairing is required."))?
                                .clone(),
                            inbox
                                .as_ref()
                                .ok_or(err("Missing receiver queue."))?
                                .clone(),
                            "127.0.0.1:0"
                                .parse()
                                .map_err(|_| err("Invalid internal loopback address."))?,
                        )
                        .await?,
                    );
                    let address = peer.local_addr()?;
                    server = Some(peer);
                    Ok(Reply::Listening { address })
                }
                Control::Arm {} => {
                    require(served.is_none(), "A receiver request is already armed.")?;
                    let peer = server
                        .as_ref()
                        .ok_or(err("Paired receiver listener is required."))?
                        .clone();
                    served = Some(tokio::spawn(async move { peer.serve_one().await }));
                    Ok(Reply::Armed {})
                }
                Control::Wait {} => {
                    let result = served
                        .take()
                        .ok_or(err("No armed receiver request."))?
                        .await
                        .map_err(|_| err("Receiver task failed."))?;
                    Ok(Reply::Served { ok: result.is_ok() })
                }
                Control::Send {
                    address,
                    retry_only,
                } => {
                    require(
                        init.role == Role::Sender
                            && address.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST)
                            && address.port() > 0,
                        "Only generated loopback sender requests are supported.",
                    )?;
                    if retry_only && outbox.is_none() {
                        return Ok(Reply::Sent {
                            ok: false,
                            failure_class: Some("no_outbox".into()),
                            receipt: None,
                        });
                    }
                    let paired = pair.as_ref().ok_or(err("Explicit pairing is required."))?;
                    if outbox.is_none() {
                        outbox = Some(Envelope::new(
                            paired,
                            1,
                            ZERO_DIGEST,
                            vec![Change::Put {
                                path: FIXTURE_PATH.into(),
                                hash: hash(FIXTURE_BYTES),
                                bytes: FIXTURE_BYTES.to_vec(),
                                permissions: permissions(),
                            }],
                        )?);
                    }
                    match PeerClient::new(paired.clone())?
                        .send(address, outbox.as_ref().ok_or(err("Missing RAM outbox."))?)
                        .await
                    {
                        Ok(receipt) => Ok(Reply::Sent {
                            ok: true,
                            failure_class: None,
                            receipt: Some(receipt),
                        }),
                        Err(error) => Ok(Reply::Sent {
                            ok: false,
                            failure_class: Some(failure_class(&error)),
                            receipt: None,
                        }),
                    }
                }
                Control::Status {} => {
                    let pending = if let Some(inbox) = &inbox {
                        inbox
                            .lock()
                            .map_err(|_| err("Private queue is unavailable."))?
                            .pending_count()?
                    } else {
                        0
                    };
                    Ok(Reply::Status {
                        pending,
                        paired: pair.is_some(),
                        has_outbox: outbox.is_some(),
                        workspace_absent: !root.join("workspace").exists()
                            && !root.join("src").exists(),
                    })
                }
                Control::Review {
                    pairing_id,
                    sequence,
                    digest,
                } => {
                    require(
                        init.role == Role::Receiver
                            && hex(&pairing_id)
                            && hex(&digest)
                            && sequence == 1,
                        "Only exact fixed-fixture receipt review is supported.",
                    )?;
                    let proposal = inbox
                        .as_ref()
                        .ok_or(err("Missing receiver queue."))?
                        .lock()
                        .map_err(|_| err("Private queue unavailable."))?
                        .review(&pairing_id, sequence, &digest)?;
                    require(
                        proposal.changes.len() == 1,
                        "Unexpected reviewed fixture change count.",
                    )?;
                    let Change::Put {
                        path,
                        bytes,
                        hash: expected,
                        ..
                    } = &proposal.changes[0]
                    else {
                        return Err(err("Unexpected reviewed fixture kind."));
                    };
                    require(
                        path == FIXTURE_PATH
                            && bytes == FIXTURE_BYTES
                            && *expected == hash(FIXTURE_BYTES),
                        "Reviewed queue is not the fixed generated fixture.",
                    )?;
                    Ok(Reply::Reviewed {
                        digest,
                        payload_hash: hash(bytes),
                        changes: 1,
                    })
                }
                Control::Init { .. } => Err(err("Worker initialization cannot be repeated.")),
            }
        }
        .await;
        write_json(&mut output, &reply.unwrap_or(Reply::Failure {}))?;
    }
}
struct Reader {
    pipe: BufReader<ChildStdout>,
    test_boot: bool,
}
struct Process {
    child: Child,
    input: Arc<Mutex<ChildStdin>>,
    output: Arc<Mutex<Reader>>,
    pid: u32,
    alive: bool,
}
struct SpawnGuard(Option<Child>);
impl Drop for SpawnGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if self.alive {
            let _ = self.child.kill();
            let _ = self.child.wait();
            self.alive = false;
        }
    }
}
impl Process {
    async fn spawn(init: Init) -> PeerResult<(Self, PairingOffer)> {
        let mut command = Command::new(io(std::env::current_exe())?);
        #[cfg(not(test))]
        command.arg("--worker");
        #[cfg(test)]
        command
            .args([
                "--exact",
                "tests::worker_entry",
                "--ignored",
                "--nocapture",
                "--quiet",
            ])
            .env("DEVDROP_PROCESS_LOCALHOST_WORKER", "1");
        let mut spawned = SpawnGuard(Some(io(command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn())?));
        let child = spawned
            .0
            .as_mut()
            .ok_or(err("Missing guarded worker process."))?;
        let pid = child.id();
        let input = child
            .stdin
            .take()
            .ok_or(err("Missing anonymous worker input pipe."))?;
        let output = child
            .stdout
            .take()
            .ok_or(err("Missing anonymous worker output pipe."))?;
        let input = Arc::new(Mutex::new(input));
        let output = Arc::new(Mutex::new(Reader {
            pipe: BufReader::new(output),
            test_boot: cfg!(test),
        }));
        let process = Self {
            child: spawned
                .0
                .take()
                .ok_or(err("Missing guarded worker process."))?,
            input,
            output,
            pid,
            alive: true,
        };
        process.send(Control::Init { init }).await?;
        let Reply::Hello {
            pid: reported,
            offer,
        } = process.receive().await?
        else {
            return Err(err("Expected public ephemeral worker offer."));
        };
        require(
            pid == reported,
            "Worker PID does not match spawned process.",
        )?;
        Ok((process, offer))
    }
    async fn send(&self, command: Control) -> PeerResult<()> {
        let pipe = self.input.clone();
        timeout(
            CONTROL_TIMEOUT,
            tokio::task::spawn_blocking(move || {
                write_json(
                    &mut *pipe.lock().map_err(|_| err("Worker pipe unavailable."))?,
                    &command,
                )
            }),
        )
        .await
        .map_err(|_| err("Worker control write timed out."))?
        .map_err(|_| err("Worker control writer failed."))?
    }
    async fn receive(&self) -> PeerResult<Reply> {
        let pipe = self.output.clone();
        timeout(
            CONTROL_TIMEOUT,
            tokio::task::spawn_blocking(move || {
                let mut reader = pipe.lock().map_err(|_| err("Worker pipe unavailable."))?;
                if reader.test_boot {
                    // libtest's ignored child helper emits only this bounded startup
                    // boilerplate. Normal example binaries have strictly JSON pipes.
                    let first = read_line_bounded(&mut reader.pipe)?;
                    require(
                        first == b"\nrunning 1 test\n"
                            || first == b"\n"
                            || first == b"running 1 test\n",
                        "Unexpected test worker startup frame.",
                    )?;
                    if first == b"\n" {
                        require(
                            read_line_bounded(&mut reader.pipe)? == b"running 1 test\n",
                            "Unexpected test worker startup frame.",
                        )?;
                    }
                    reader.test_boot = false;
                }
                read_json(&mut reader.pipe)
            }),
        )
        .await
        .map_err(|_| err("Worker control read timed out."))?
        .map_err(|_| err("Worker control reader failed."))?
    }
    async fn request(&self, command: Control) -> PeerResult<Reply> {
        self.send(command).await?;
        self.receive().await
    }
    fn kill_now(&mut self) -> PeerResult<()> {
        require(
            self.alive && io(self.child.try_wait())?.is_none(),
            "Expected a live fixture worker for hard kill.",
        )?;
        io(self.child.kill())?;
        let status = io(self.child.wait())?;
        self.alive = false;
        require(
            !status.success(),
            "Hard-killed fixture worker unexpectedly exited successfully.",
        )
    }
}
#[derive(Clone, Copy)]
enum Fault {
    Flip,
    Cut,
    DropAck,
    Transparent,
}
impl Fault {
    fn name(self) -> &'static str {
        match self {
            Self::Flip => "encrypted_record_bitflip",
            Self::Cut => "mid_tls_flight_cut",
            Self::DropAck => "post_commit_ack_drop",
            Self::Transparent => "transparent_exact_retry",
        }
    }
}
#[derive(Default, Serialize)]
struct ProxyStats {
    case: String,
    c2s_bytes: u64,
    s2c_bytes: u64,
    c2s_encrypted_records: usize,
    fault_fired: bool,
}
struct Proxy {
    address: SocketAddr,
    task: Option<JoinHandle<PeerResult<ProxyStats>>>,
}
impl Drop for Proxy {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
async fn tls_record(reader: &mut (impl AsyncRead + Unpin)) -> PeerResult<Option<Vec<u8>>> {
    let mut header = [0u8; 5];
    match reader.read_exact(&mut header[..1]).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(_) => return Err(err("Loopback proxy record read failed.")),
    };
    reader
        .read_exact(&mut header[1..])
        .await
        .map_err(|_| err("Loopback proxy TLS header interrupted."))?;
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    require(
        length > 0 && length <= 18 * 1024,
        "Loopback proxy TLS record exceeded bound.",
    )?;
    let mut record = Vec::with_capacity(5 + length);
    record.extend_from_slice(&header);
    record.resize(5 + length, 0);
    reader
        .read_exact(&mut record[5..])
        .await
        .map_err(|_| err("Loopback proxy TLS record interrupted."))?;
    Ok(Some(record))
}
async fn forward(
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
    c2s: bool,
    fault: Fault,
    encrypted: Arc<AtomicUsize>,
    stats: Arc<Mutex<ProxyStats>>,
) -> PeerResult<()> {
    while let Some(mut record) = tls_record(&mut reader).await? {
        let length = record.len() as u64;
        {
            let mut stats = stats
                .lock()
                .map_err(|_| err("Proxy counters unavailable."))?;
            if c2s {
                stats.c2s_bytes += length;
            } else {
                stats.s2c_bytes += length;
            }
            require(
                stats.c2s_bytes + stats.s2c_bytes <= 512 * 1024,
                "Proxy byte budget exceeded.",
            )?;
        }
        let encrypted_record = record[0] == 23;
        let count = if c2s && encrypted_record {
            encrypted.fetch_add(1, Ordering::SeqCst) + 1
        } else {
            encrypted.load(Ordering::SeqCst)
        };
        if c2s && encrypted_record && count == 1 && matches!(fault, Fault::Flip | Fault::Cut) {
            stats
                .lock()
                .map_err(|_| err("Proxy counters unavailable."))?
                .fault_fired = true;
            if matches!(fault, Fault::Flip) {
                let last = record.len() - 1;
                record[last] ^= 1;
            } else {
                let partial = 5 + (record.len() - 5) / 2;
                writer
                    .write_all(&record[..partial])
                    .await
                    .map_err(|_| err("Proxy interrupted-flight write failed."))?;
                writer
                    .flush()
                    .await
                    .map_err(|_| err("Proxy interrupted-flight flush failed."))?;
                return Ok(());
            }
        }
        if !c2s && encrypted_record && count >= 2 && matches!(fault, Fault::DropAck) {
            stats
                .lock()
                .map_err(|_| err("Proxy counters unavailable."))?
                .fault_fired = true;
            return Ok(());
        }
        writer
            .write_all(&record)
            .await
            .map_err(|_| err("Loopback proxy forwarding ended."))?;
        writer
            .flush()
            .await
            .map_err(|_| err("Loopback proxy flush ended."))?;
    }
    Ok(())
}
impl Proxy {
    async fn start(destination: SocketAddr, fault: Fault) -> PeerResult<Self> {
        require(
            destination.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST),
            "Proxy destination must be generated loopback.",
        )?;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| err("Loopback proxy bind failed."))?;
        let address = io(listener.local_addr())?;
        let task = tokio::spawn(async move {
            timeout(Duration::from_secs(6), async move {
                let (client, _) = listener
                    .accept()
                    .await
                    .map_err(|_| err("Loopback proxy accept failed."))?;
                let server = TcpStream::connect(destination)
                    .await
                    .map_err(|_| err("Loopback proxy destination failed."))?;
                let (ar, aw) = client.into_split();
                let (br, bw) = server.into_split();
                let encrypted = Arc::new(AtomicUsize::new(0));
                let stats = Arc::new(Mutex::new(ProxyStats {
                    case: fault.name().into(),
                    ..ProxyStats::default()
                }));
                let up = forward(ar, bw, true, fault, encrypted.clone(), stats.clone());
                let down = forward(br, aw, false, fault, encrypted.clone(), stats.clone());
                tokio::pin!(up, down);
                tokio::select! {_ = &mut up=>{},_ = &mut down=>{}}
                let mut result = stats
                    .lock()
                    .map_err(|_| err("Proxy counters unavailable."))?;
                result.c2s_encrypted_records = encrypted.load(Ordering::SeqCst);
                Ok(ProxyStats {
                    case: result.case.clone(),
                    c2s_bytes: result.c2s_bytes,
                    s2c_bytes: result.s2c_bytes,
                    c2s_encrypted_records: result.c2s_encrypted_records,
                    fault_fired: result.fault_fired,
                })
            })
            .await
            .map_err(|_| err("Loopback proxy exceeded bounded test time."))?
        });
        Ok(Self {
            address,
            task: Some(task),
        })
    }
    async fn finish(mut self) -> PeerResult<ProxyStats> {
        self.task
            .take()
            .ok_or(err("Missing proxy task."))?
            .await
            .map_err(|_| err("Proxy worker failed."))?
    }
}
fn make_root(base: &Path, role: Role, nonce: &str) -> PeerResult<PathBuf> {
    let root = base.join(role.name());
    private_dir(&root)?;
    let marker = Marker {
        schema: MARKER_SCHEMA.into(),
        nonce: nonce.into(),
        coordinator_pid: std::process::id(),
        role,
    };
    let bytes = serde_json::to_vec(&marker).map_err(|_| err("Fixture marker encoding failed."))?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = io(options.open(root.join(MARKER)))?;
    io(file.write_all(&bytes))?;
    io(file.sync_all())?;
    Ok(root)
}
fn init(root: &Path, role: Role, nonce: &str, reopen: bool) -> Init {
    Init {
        root: root.to_path_buf(),
        nonce: nonce.into(),
        coordinator_pid: std::process::id(),
        role,
        reopen,
    }
}
async fn confirm(process: &Process, remote: &PairingOffer) -> PeerResult<String> {
    let Reply::Paired { pairing_id } = process
        .request(Control::Pair {
            remote: remote.clone(),
            confirmed_fingerprint: remote.fingerprint.clone(),
            scope: scope(),
        })
        .await?
    else {
        return Err(err("Explicit worker pairing failed."));
    };
    Ok(pairing_id)
}
async fn listen(process: &Process) -> PeerResult<SocketAddr> {
    let Reply::Listening { address } = process.request(Control::Listen {}).await? else {
        return Err(err("Expected paired loopback listener."));
    };
    require(
        address.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST) && address.port() > 0,
        "Worker listener is outside loopback.",
    )?;
    Ok(address)
}
async fn arm(process: &Process) -> PeerResult<()> {
    require(
        matches!(process.request(Control::Arm {}).await?, Reply::Armed {}),
        "Receiver did not arm one bounded request.",
    )
}
async fn status(process: &Process, expected: u32, paired: bool, outbox: bool) -> PeerResult<()> {
    let Reply::Status {
        pending,
        paired: actual,
        has_outbox,
        workspace_absent,
    } = process.request(Control::Status {}).await?
    else {
        return Err(err("Expected sanitized worker status."));
    };
    require(
        pending == expected && actual == paired && has_outbox == outbox && workspace_absent,
        "Worker status, RAM state or queue-only boundary differed.",
    )
}
async fn reviewed(process: &Process, pairing_id: &str, digest: &str) -> PeerResult<()> {
    let Reply::Reviewed {
        digest: saved,
        payload_hash,
        changes,
    } = process
        .request(Control::Review {
            pairing_id: pairing_id.into(),
            sequence: 1,
            digest: digest.into(),
        })
        .await?
    else {
        return Err(err("Expected local-only queued fixture review."));
    };
    require(
        saved == digest && payload_hash == hash(FIXTURE_BYTES) && changes == 1,
        "Durable reviewed fixture did not match its receipt.",
    )
}
fn identity(role: &str, stage: &str, process: &Process, offer: &PairingOffer) -> Value {
    json!({"role":role,"stage":stage,"pid":process.pid,"fingerprint":offer.fingerprint})
}
async fn run() -> PeerResult<Value> {
    let temp = io(tempfile::Builder::new()
        .prefix("devdrop-process-localhost-")
        .tempdir())?;
    let base = io(fs::canonicalize(temp.path()))?;
    #[cfg(windows)]
    access::make_disposable_test_directory_private(&base).map_err(err)?;
    let mut random = [0u8; 32];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| err("Fixture nonce generation failed."))?;
    let nonce = hash(&random);
    let sender_root = make_root(&base, Role::Sender, &nonce)?;
    let receiver_root = make_root(&base, Role::Receiver, &nonce)?;
    let (mut a, ao) = Process::spawn(init(&sender_root, Role::Sender, &nonce, false)).await?;
    let (mut b, bo) = Process::spawn(init(&receiver_root, Role::Receiver, &nonce, false)).await?;
    require(
        a.pid != b.pid
            && a.pid != std::process::id()
            && b.pid != std::process::id()
            && ao.fingerprint != bo.fingerprint,
        "Peers did not get distinct process identities.",
    )?;
    let mut identities = vec![
        identity("sender", "initial", &a, &ao),
        identity("receiver", "initial", &b, &bo),
    ];
    let pairing_id = confirm(&a, &bo).await?;
    require(
        confirm(&b, &ao).await? == pairing_id,
        "Both explicit approvals did not bind the same scope/offers.",
    )?;
    let endpoint = listen(&b).await?;
    status(&a, 0, true, false).await?;
    status(&b, 0, true, false).await?;
    let mut proxies = Vec::new();
    let mut queued_digest = None;
    for fault in [Fault::Flip, Fault::Cut, Fault::DropAck, Fault::Transparent] {
        arm(&b).await?;
        let proxy = Proxy::start(endpoint, fault).await?;
        let address = proxy.address;
        let reply = a
            .request(Control::Send {
                address,
                retry_only: !matches!(fault, Fault::Flip),
            })
            .await?;
        let Reply::Sent {
            ok,
            failure_class: _,
            receipt,
        } = reply
        else {
            return Err(err("Expected bounded sender outcome."));
        };
        let stats = proxy.finish().await?;
        let Reply::Served { ok: server_ok } = b.request(Control::Wait {}).await? else {
            return Err(err("Expected receiver request completion."));
        };
        match fault {
            Fault::Flip | Fault::Cut => {
                require(
                    !ok && !server_ok && stats.fault_fired,
                    "TLS tamper/interruption did not fail closed.",
                )?;
                status(&b, 0, true, false).await?;
            }
            Fault::DropAck => {
                require(
                    !ok && stats.fault_fired && stats.c2s_encrypted_records >= 2,
                    "TLS acknowledgement gate was not observed; no ack-loss claim is valid.",
                )?;
                status(&b, 1, true, false).await?;
            }
            Fault::Transparent => {
                let receipt = receipt.ok_or(err("Missing exact-retry receipt."))?;
                require(
                    ok && server_ok
                        && receipt.status == ReceiptStatus::Duplicate
                        && receipt.pending_count == 1
                        && receipt.pairing_id == pairing_id,
                    "Lost-ack exact retry was not one durable proposal.",
                )?;
                queued_digest = Some(receipt.digest);
                status(&b, 1, true, false).await?;
            }
        }
        proxies.push(stats);
    }
    let queued_digest = queued_digest.ok_or(err("No durable proposal receipt."))?;
    reviewed(&b, &pairing_id, &queued_digest).await?;
    b.kill_now()?;
    let (mut b2, b2o) = Process::spawn(init(&receiver_root, Role::Receiver, &nonce, true)).await?;
    require(
        b2.pid != b.pid && b2o.fingerprint != bo.fingerprint,
        "Receiver process restart resumed the old RAM identity.",
    )?;
    identities.push(identity("receiver", "after_first_kill", &b2, &b2o));
    status(&b2, 1, false, false).await?;
    reviewed(&b2, &pairing_id, &queued_digest).await?;
    // A unilateral fresh receiver approval cannot silently migrate old A's pin.
    confirm(&b2, &ao).await?;
    let fresh_endpoint = listen(&b2).await?;
    arm(&b2).await?;
    let Reply::Sent {
        ok,
        failure_class,
        receipt: _,
    } = a
        .request(Control::Send {
            address: fresh_endpoint,
            retry_only: true,
        })
        .await?
    else {
        return Err(err("Expected stale identity rejection."));
    };
    require(
        !ok && failure_class.as_deref() == Some("server_tls"),
        "Old sender trust unexpectedly authenticated a new receiver certificate.",
    )?;
    require(
        matches!(
            b2.request(Control::Wait {}).await?,
            Reply::Served { ok: false }
        ),
        "New receiver unexpectedly accepted old pairing.",
    )?;
    status(&b2, 1, true, false).await?;
    a.kill_now()?;
    b2.kill_now()?;
    let (a2, a2o) = Process::spawn(init(&sender_root, Role::Sender, &nonce, false)).await?;
    let (b3, b3o) = Process::spawn(init(&receiver_root, Role::Receiver, &nonce, true)).await?;
    require(
        a2.pid != a.pid
            && a2o.fingerprint != ao.fingerprint
            && b3o.fingerprint != b2o.fingerprint
            && b3.pid != b2.pid,
        "Restarted peers did not generate fresh RAM identities.",
    )?;
    identities.push(identity("sender", "after_kill", &a2, &a2o));
    identities.push(identity("receiver", "after_second_kill", &b3, &b3o));
    status(&a2, 0, false, false).await?;
    status(&b3, 1, false, false).await?;
    require(
        matches!(a2.request(Control::Send{address:fresh_endpoint,retry_only:true}).await?,Reply::Sent{ok:false,failure_class:Some(class),receipt:None} if class=="no_outbox"),
        "Restarted sender resumed an old RAM outbox.",
    )?;
    reviewed(&b3, &pairing_id, &queued_digest).await?;
    let new_pairing_id = confirm(&a2, &b3o).await?;
    require(
        confirm(&b3, &a2o).await? == new_pairing_id && new_pairing_id != pairing_id,
        "New explicit pairing was not fresh.",
    )?;
    let new_endpoint = listen(&b3).await?;
    arm(&b3).await?;
    let Reply::Sent {
        ok,
        receipt: Some(receipt),
        ..
    } = a2
        .request(Control::Send {
            address: new_endpoint,
            retry_only: false,
        })
        .await?
    else {
        return Err(err("Expected explicit re-pair requeue receipt."));
    };
    require(
        ok && receipt.status == ReceiptStatus::Queued
            && receipt.pairing_id == new_pairing_id
            && receipt.pending_count == 1,
        "Explicit new pairing did not queue exactly one new proposal.",
    )?;
    require(
        matches!(
            b3.request(Control::Wait {}).await?,
            Reply::Served { ok: true }
        ),
        "Explicit re-pair receiver did not commit.",
    )?;
    status(&b3, 2, true, false).await?;
    reviewed(&b3, &new_pairing_id, &receipt.digest).await?;
    let check_names = [
        "distinct_peer_processes_and_ram_identities",
        "both_explicit_pairing_confirmations_bound",
        "encrypted_tls_record_bitflip_refused_before_queue",
        "mid_tls_flight_interruption_refused_before_queue",
        "post_commit_ack_loss_observed_by_actual_queue",
        "exact_authenticated_retry_is_one_duplicate",
        "queue_only_no_workspace_writes",
        "receiver_hard_kill_retains_private_sqlite_proposal",
        "new_receiver_certificate_rejects_old_sender_trust",
        "sender_hard_kill_drops_identity_and_ram_outbox",
        "old_payload_remains_local_reviewable_after_restart",
        "fresh_explicit_pairing_required_for_new_requeue",
    ];
    Ok(
        json!({"schema":"devdrop-process-localhost-evidence/v1","topology":{"machines":1,"minimum_concurrent_processes":3,"peer_processes_spawned":5,"address_spaces":"separate-child-processes"},"cross_device":false,"process_kill":true,"vm_reboot":false,"physical_network_outage":false,"transport":"loopback-tls13-mtls","runtime":{"os":std::env::consts::OS,"arch":std::env::consts::ARCH,"coordinator_pid":std::process::id()},"identities":identities,"proxy":proxies,"checks":check_names.into_iter().map(|name|json!({"name":name,"passed":true})).collect::<Vec<_>>(),"queue_counts":{"after_lost_ack_retry":1,"after_explicit_new_pairing":2},"trust_boundary":"One native OS and real child processes. No private VM, device reboot, physical network outage or persisted production identity was tested.","ack_gate":"TLS1.3 record gate observed and queue commit independently verified; no ciphertext, payload or private key is reported."}),
    )
}
async fn acceptance() -> PeerResult<Value> {
    timeout(TOTAL_TIMEOUT, run())
        .await
        .map_err(|_| err("Process-localhost acceptance exceeded forty seconds."))?
}
fn runtime() -> PeerResult<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|_| err("Fixture async runtime unavailable."))
}
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = runtime().and_then(|runtime| {
        if args.is_empty() {
            runtime.block_on(acceptance()).and_then(|report| {
                println!(
                    "{}",
                    serde_json::to_string(&report)
                        .map_err(|_| err("Sanitized evidence encoding failed."))?
                );
                Ok(())
            })
        } else if args == ["--worker"] {
            runtime.block_on(worker())
        } else {
            Err(err(
                "This fixture accepts no paths, addresses or credentials.",
            ))
        }
    });
    if let Err(error) = result {
        eprintln!("{}", error.0);
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "Internal child worker; invoked only by the bounded process acceptance test."]
    fn worker_entry() {
        if std::env::var_os("DEVDROP_PROCESS_LOCALHOST_WORKER").is_some() {
            runtime().unwrap().block_on(worker()).unwrap();
        }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_peer_process_kill_restart_and_tls_proxy_faults() {
        let report = acceptance()
            .await
            .expect("Bounded native process acceptance must pass.");
        assert_eq!(report["cross_device"], false);
        assert_eq!(report["process_kill"], true);
        assert!(report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|check| check["passed"] == true));
        let serialized = report.to_string();
        for forbidden in [
            "certificate_der",
            "PRIVATE KEY",
            "run-marker",
            "payload_hash",
            "generated real peer process fixture",
        ] {
            assert!(
                !serialized.contains(forbidden),
                "Final evidence must omit private control and payload material."
            );
        }
    }
    #[test]
    fn control_schema_and_scratch_namespace_fail_closed() {
        assert!(
            serde_json::from_value::<Control>(json!({"command":"apply","path":"/outside"}))
                .is_err()
        );
        assert!(serde_json::from_value::<Control>(
            json!({"command":"status","read_path":"outside"})
        )
        .is_err());
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        assert!(validate_init(&Init {
            root,
            nonce: ZERO_DIGEST.into(),
            coordinator_pid: 1,
            role: Role::Receiver,
            reopen: false
        })
        .is_err());
        let mut bytes = std::io::Cursor::new(vec![b'x'; CONTROL_LIMIT + 1]);
        assert!(read_line_bounded(&mut bytes).is_err());
    }
}
