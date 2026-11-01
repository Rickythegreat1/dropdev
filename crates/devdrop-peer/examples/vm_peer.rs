//! Off-default disposable QEMU worker. It has no mount, route, firewall, reboot,
//! process-kill, project-read, stage or apply operations. PID1 owns infrastructure.
use devdrop_core::file_permissions as access;
use devdrop_peer::{
    pairing::{Paired, PairingFlow, PairingOffer, Scope},
    store::Inbox,
    transport::vm_fixture::{self, Fault},
    wire::{Change, Envelope, Receipt, ZERO_DIGEST},
    PeerError, PeerResult,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Read, Write},
    path::{Component, Path},
    sync::{Arc, Mutex},
};
use tokio::task::JoinHandle;
const LIMIT: usize = 64 * 1024;
const STATE: &str = "/state/devdrop-fixture";
const MARKER: &str = "/state/devdrop-fixture-kind";
const MARKER_BYTES: &[u8] = b"devdrop-isolated-vm-fixture-v1\n";
fn io<T>(value: std::io::Result<T>) -> PeerResult<T> {
    value.map_err(|_| PeerError("Generated guest fixture IO unavailable."))
}
fn require(value: bool, message: &'static str) -> PeerResult<()> {
    if value {
        Ok(())
    } else {
        Err(PeerError(message))
    }
}
fn hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    A,
    B,
}
#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Control {
    Pair {
        remote: PairingOffer,
        confirmed_fingerprint: String,
        scope: Scope,
    },
    Listen {},
    Arm {},
    Wait {},
    Send {},
    Retry {},
    TamperHash {},
    DeleteOutsideScope {},
    SequenceQuota {},
    Status {},
    Review {
        pairing_id: String,
        sequence: u64,
        digest: String,
    },
}
#[derive(Serialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
enum Reply {
    Offer {
        schema: &'static str,
        pid: u32,
        offer: PairingOffer,
        scope: Scope,
    },
    Paired {
        pairing_id: String,
    },
    Listening {
        address: String,
    },
    Armed {},
    Served {
        ok: bool,
        receipt: Option<Receipt>,
        failure_class: Option<&'static str>,
    },
    Sent {
        ok: bool,
        receipt: Option<Receipt>,
        failure_class: Option<&'static str>,
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
    Failure {
        failure_class: &'static str,
    },
}
fn read_control(reader: &mut impl BufRead) -> PeerResult<Control> {
    let mut bytes = Vec::new();
    loop {
        let input = io(reader.fill_buf())?;
        require(!input.is_empty(), "Guest control pipe closed.")?;
        let end = input.iter().position(|b| *b == b'\n').map(|n| n + 1);
        let count = end.unwrap_or(input.len());
        require(
            bytes.len() + count <= LIMIT,
            "Guest serial control exceeds hard limit.",
        )?;
        bytes.extend_from_slice(&input[..count]);
        reader.consume(count);
        if end.is_some() {
            break;
        }
    }
    serde_json::from_slice(&bytes).map_err(|_| PeerError("Invalid strict guest control schema."))
}
fn reply(writer: &mut impl Write, value: &Reply) -> PeerResult<()> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| PeerError("Guest public response encoding failed."))?;
    require(bytes.len() < LIMIT, "Guest response exceeds hard limit.")?;
    io(writer.write_all(&bytes))?;
    io(writer.write_all(b"\n"))?;
    io(writer.flush())
}
fn bounded_file(path: &Path, limit: usize) -> PeerResult<Vec<u8>> {
    let metadata = io(fs::symlink_metadata(path))?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= limit as u64,
        "Guest fixture marker type or size is invalid.",
    )?;
    let mut bytes = Vec::new();
    io(io(File::open(path))?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes))?;
    require(bytes.len() <= limit, "Guest fixture marker exceeds limit.")?;
    Ok(bytes)
}
fn boot_flag(bytes: &[u8]) -> bool {
    bytes
        .split(u8::is_ascii_whitespace)
        .any(|word| word == b"devdrop_vm_fixture=1")
}
fn validate_guest(role: Role) -> PeerResult<()> {
    require(
        cfg!(target_os = "linux")
            && std::env::var_os("DEVDROP_VM_FIXTURE").as_deref() == Some(std::ffi::OsStr::new("1")),
        "This separately compiled worker runs only in the marked disposable Linux guest.",
    )?;
    // Fixed kernel metadata only; no user path or arbitrary read command exists.
    let mut commandline = Vec::new();
    io(io(File::open("/proc/cmdline"))?
        .take(4097)
        .read_to_end(&mut commandline))?;
    require(
        commandline.len() <= 4096 && boot_flag(&commandline),
        "Disposable guest kernel boot marker is required.",
    )?;
    let mut partial = std::path::PathBuf::new();
    for component in Path::new(STATE).components() {
        require(
            !matches!(component, Component::ParentDir | Component::CurDir),
            "Guest state traversal refused.",
        )?;
        partial.push(component);
        let metadata = io(fs::symlink_metadata(&partial))?;
        require(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "Guest fixture state directory must not be a symlink.",
        )?;
    }
    require(
        bounded_file(Path::new(MARKER), 128)? == MARKER_BYTES,
        "Generated fixture disk marker mismatch.",
    )?;
    access::inspect_directory(&io(File::open(STATE))?).map_err(PeerError)?;
    let mut count = 0;
    for entry in io(fs::read_dir(STATE))? {
        count += 1;
        require(
            count <= 1,
            "Guest fixture state contains unexpected entries.",
        )?;
        let entry = io(entry)?;
        require(
            role == Role::B && entry.file_name() == "queue",
            "Only the generated receiver queue may persist.",
        )?;
    }
    Ok(())
}
fn failure(error: &PeerError) -> &'static str {
    if error.0 == "Mutual TLS server authentication failed." {
        "server_tls"
    } else if error.0.contains("pin") {
        "certificate_pin"
    } else if error.0.contains("timed out") {
        "timeout_uncertain"
    } else {
        "request_refused"
    }
}
async fn run(role: Role) -> PeerResult<()> {
    validate_guest(role)?;
    let mut flow = Some(PairingFlow::new_ephemeral()?);
    let own_offer = flow
        .as_ref()
        .ok_or(PeerError("Missing ephemeral guest flow."))?
        .offer();
    let inbox = if role == Role::B {
        let path = Path::new(STATE).join("queue");
        Some(Arc::new(Mutex::new(if path.exists() {
            Inbox::open(&path)?
        } else {
            Inbox::create_new(&path)?
        })))
    } else {
        None
    };
    let mut paired: Option<Paired> = None;
    let mut server: Option<Arc<vm_fixture::Server>> = None;
    let mut serving: Option<JoinHandle<PeerResult<Receipt>>> = None;
    let mut outbox: Option<Envelope> = None;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut input = BufReader::new(stdin.lock());
    let mut output = stdout.lock();
    reply(
        &mut output,
        &Reply::Offer {
            schema: "devdrop-vm-worker/v1",
            pid: std::process::id(),
            offer: own_offer,
            scope: vm_fixture::scope(),
        },
    )?;
    loop {
        let command = read_control(&mut input)?;
        let result: PeerResult<Reply> = async {
            match command {
                Control::Pair {
                    remote,
                    confirmed_fingerprint,
                    scope,
                } => {
                    require(
                        paired.is_none() && scope == vm_fixture::scope(),
                        "Guest fixture pairing scope must match exactly and be confirmed once.",
                    )?;
                    let pair = flow
                        .take()
                        .ok_or(PeerError("Guest offer already consumed."))?
                        .approve(&remote, &confirmed_fingerprint, scope)?;
                    let pairing_id = pair.id().to_owned();
                    paired = Some(pair);
                    Ok(Reply::Paired { pairing_id })
                }
                Control::Listen {} => {
                    require(
                        role == Role::B && server.is_none(),
                        "Only the receiver opens one exact fixture listener.",
                    )?;
                    let listener = Arc::new(
                        vm_fixture::Server::bind(
                            paired
                                .as_ref()
                                .ok_or(PeerError("Both-end explicit pairing is required."))?
                                .clone(),
                            inbox
                                .as_ref()
                                .ok_or(PeerError("Missing guest queue."))?
                                .clone(),
                        )
                        .await?,
                    );
                    let address = listener.local_addr()?.to_string();
                    server = Some(listener);
                    Ok(Reply::Listening { address })
                }
                Control::Arm {} => {
                    require(serving.is_none(), "Guest receiver request already armed.")?;
                    let listener = server
                        .as_ref()
                        .ok_or(PeerError("Guest receiver pairing/listener is required."))?
                        .clone();
                    serving = Some(tokio::spawn(async move { listener.serve_one().await }));
                    Ok(Reply::Armed {})
                }
                Control::Wait {} => {
                    let result = serving
                        .take()
                        .ok_or(PeerError("No guest request was armed."))?
                        .await
                        .map_err(|_| PeerError("Guest request task failed."))?;
                    Ok(match result {
                        Ok(receipt) => Reply::Served {
                            ok: true,
                            receipt: Some(receipt),
                            failure_class: None,
                        },
                        Err(error) => Reply::Served {
                            ok: false,
                            receipt: None,
                            failure_class: Some(failure(&error)),
                        },
                    })
                }
                Control::Send {}
                | Control::Retry {}
                | Control::TamperHash {}
                | Control::DeleteOutsideScope {}
                | Control::SequenceQuota {} => {
                    require(role == Role::A, "Only guest A sends the generated fixture.")?;
                    if matches!(command, Control::Retry {}) && outbox.is_none() {
                        return Ok(Reply::Sent {
                            ok: false,
                            receipt: None,
                            failure_class: Some("no_outbox"),
                        });
                    }
                    let pair = paired
                        .as_ref()
                        .ok_or(PeerError("Explicit guest pairing is required."))?;
                    if outbox.is_none() {
                        outbox = Some(Envelope::new(
                            pair,
                            1,
                            ZERO_DIGEST,
                            vec![Change::Put {
                                path: vm_fixture::FIXTURE_PATH.into(),
                                hash: hash(vm_fixture::FIXTURE_BYTES),
                                bytes: vm_fixture::FIXTURE_BYTES.to_vec(),
                                permissions: access::FilePermissions::Unix { mode: 0o600 },
                            }],
                        )?);
                    }
                    let client = vm_fixture::Client::new(pair.clone())?;
                    let proposal = outbox
                        .as_ref()
                        .ok_or(PeerError("Missing guest RAM outbox."))?;
                    let result = match command {
                        Control::TamperHash {} => {
                            client.send_fault(proposal, Fault::HashMismatch).await
                        }
                        Control::DeleteOutsideScope {} => {
                            client.send_fault(proposal, Fault::DeleteOutsideScope).await
                        }
                        Control::SequenceQuota {} => {
                            client.send_fault(proposal, Fault::SequenceQuota).await
                        }
                        _ => client.send(proposal).await,
                    };
                    Ok(match result {
                        Ok(receipt) => Reply::Sent {
                            ok: true,
                            receipt: Some(receipt),
                            failure_class: None,
                        },
                        Err(error) => Reply::Sent {
                            ok: false,
                            receipt: None,
                            failure_class: Some(failure(&error)),
                        },
                    })
                }
                Control::Status {} => {
                    let pending = if let Some(inbox) = &inbox {
                        inbox
                            .lock()
                            .map_err(|_| PeerError("Guest queue unavailable."))?
                            .pending_count()?
                    } else {
                        0
                    };
                    Ok(Reply::Status {
                        pending,
                        paired: paired.is_some(),
                        has_outbox: outbox.is_some(),
                        workspace_absent: !Path::new(STATE).join("src").exists()
                            && !Path::new(STATE).join("workspace").exists(),
                    })
                }
                Control::Review {
                    pairing_id,
                    sequence,
                    digest,
                } => {
                    require(
                        role == Role::B && sequence == 1 && hex(&pairing_id) && hex(&digest),
                        "Only exact local generated queue review is allowed.",
                    )?;
                    let envelope = inbox
                        .as_ref()
                        .ok_or(PeerError("Missing guest queue."))?
                        .lock()
                        .map_err(|_| PeerError("Guest queue unavailable."))?
                        .review(&pairing_id, sequence, &digest)?;
                    require(
                        envelope.changes.len() == 1,
                        "Reviewed guest fixture count differs.",
                    )?;
                    let Change::Put {
                        path,
                        hash: expected,
                        bytes,
                        ..
                    } = &envelope.changes[0]
                    else {
                        return Err(PeerError("Reviewed guest fixture kind differs."));
                    };
                    require(
                        path == vm_fixture::FIXTURE_PATH
                            && bytes == vm_fixture::FIXTURE_BYTES
                            && *expected == hash(vm_fixture::FIXTURE_BYTES),
                        "Reviewed guest payload is outside the exact generated fixture.",
                    )?;
                    Ok(Reply::Reviewed {
                        digest,
                        payload_hash: hash(bytes),
                        changes: 1,
                    })
                }
            }
        }
        .await;
        reply(
            &mut output,
            &result.unwrap_or(Reply::Failure {
                failure_class: "invalid_control_or_state",
            }),
        )?;
    }
}
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let role = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["a"] => Role::A,
        ["b"] => Role::B,
        _ => {
            eprintln!("vm_peer accepts only fixed guest role a or b.");
            std::process::exit(1);
        }
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build();
    let result = runtime
        .map_err(|_| PeerError("Guest runtime unavailable."))
        .and_then(|runtime| runtime.block_on(run(role)));
    if let Err(error) = result {
        eprintln!("{}", error.0);
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn strict_fixed_control_and_boot_markers() {
        for command in [
            json!({"command":"reboot"}),
            json!({"command":"send","address":"1.2.3.4:80"}),
            json!({"command":"status","path":"/outside"}),
            json!({"command":"apply"}),
        ] {
            assert!(serde_json::from_value::<Control>(command).is_err());
        }
        assert!(boot_flag(b"console=ttyS0 devdrop_vm_fixture=1 panic=1"));
        assert!(!boot_flag(b"devdrop_vm_fixture=10"));
        assert!(validate_guest(Role::A).is_err());
    }
    #[test]
    fn bounded_control_before_allocation() {
        let mut input = std::io::Cursor::new(vec![b'x'; LIMIT + 1]);
        assert!(read_control(&mut input).is_err());
        let mut input = std::io::Cursor::new(b"{\"command\":\"status\"}\n".to_vec());
        assert!(matches!(
            read_control(&mut input).unwrap(),
            Control::Status {}
        ));
    }
}
