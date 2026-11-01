#!/usr/bin/env python3
"""Public-CI-only two-guest fixture; an inherited Unix socket is the entire network.

Never execute guest init on the host. No host package installation, bridge, TAP,
NAT, route, firewall, DNS, SSH, listening host socket or user workspace is used.
"""
from pathlib import Path
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
import re
import selectors
import signal
import socket
import stat
import struct
import subprocess
import tempfile
import time

_spec = importlib.util.spec_from_file_location('readiness', Path(__file__).with_name('isolated-vm-readiness.py'))
readiness = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(readiness)
command, require, sha = readiness.command, readiness.require, readiness.sha
SCHEMA = 'devdrop-isolated-vm-transport/v1'
SCOPE = dict(channel='isolated-two-guest-fixture', paths=['src/shared.txt'], allow_delete=False,
             max_messages=1, max_bytes_per_proposal=4096, max_total_bytes=4096)
HEX = re.compile('[0-9a-f]{64}')
LIBRARIES = frozenset(('libc.so.6', 'libm.so.6', 'libgcc_s.so.1', 'libpthread.so.0',
                       'libdl.so.2', 'librt.so.1', 'ld-linux-x86-64.so.2'))


def elf_sections(data):
    require(data[:6] == b'\x7fELF\x02\x01', 'Expected reviewed x86_64 little-endian ELF')
    require(len(data) >= 64, 'Truncated ELF header')
    require(struct.unpack_from('<H', data, 18)[0] == 62, 'Only x86_64 ELF guest components are supported')
    offset = struct.unpack_from('<Q', data, 40)[0]
    size, count, strings = struct.unpack_from('<HHH', data, 58)
    require(size >= 64 and 0 < count <= 4096 and strings < count and offset + size * count <= len(data), 'Invalid ELF section table')
    entries = [struct.unpack_from('<IIQQQQIIQQ', data, offset + i * size) for i in range(count)]
    names = entries[strings]
    require(names[4] + names[5] <= len(data), 'Invalid ELF names')
    table = data[names[4]:names[4] + names[5]]
    result = {}
    for entry in entries:
        require(entry[0] < len(table) and (entry[1] == 8 or entry[4] + entry[5] <= len(data)), 'Invalid ELF section bounds')
        end = table.find(b'\0', entry[0]); require(end >= 0, 'Invalid ELF name terminator')
        name = table[entry[0]:end].decode('ascii')
        result[name] = (entry, b'' if entry[1] == 8 else data[entry[4]:entry[4] + entry[5]])
    return result, entries


def module_dependencies(path):
    sections, _ = elf_sections(Path(path).read_bytes())
    require('.modinfo' in sections, 'Kernel module lacks official metadata')
    fields = [part[8:] for part in sections['.modinfo'][1].split(b'\0') if part.startswith(b'depends=')]
    require(len(fields) == 1, 'Kernel module dependencies ambiguous')
    names = fields[0].decode('ascii').split(',') if fields[0] else []
    require(all(re.fullmatch('[a-zA-Z0-9_+-]{1,80}', name) for name in names), 'Invalid module dependency')
    return names


def module_closure(module_root, wanted=('virtio_net', 'virtio_pci', 'virtio_blk', 'ext4')):
    root = Path(module_root).resolve(strict=True)
    available = {}
    for path in root.rglob('*.ko'):
        require(path.resolve().is_relative_to(root) and not path.is_symlink(), 'Module path escaped official extraction')
        name = path.stem.replace('-', '_')
        require(name not in available, 'Ambiguous official module name')
        available[name] = path
    builtin_file = root / 'modules.builtin'
    builtin = {Path(line).stem.replace('-', '_') for line in builtin_file.read_text().splitlines()} if builtin_file.is_file() else set()
    result, visiting, done = [], set(), set()
    def visit(name):
        name = name.replace('-', '_')
        if name in done or name in builtin: return
        require(name not in visiting and name in available, 'Missing or cyclic official module dependency: ' + name)
        visiting.add(name)
        for dependency in module_dependencies(available[name]): visit(dependency)
        visiting.remove(name); done.add(name); result.append(available[name])
    for name in wanted: visit(name)
    require(len(result) <= 48 and sum(p.stat().st_size for p in result) <= 64 * 1024 * 1024, 'Kernel module closure exceeds fixture budget')
    return result


def needed_libraries(path):
    sections, entries = elf_sections(Path(path).read_bytes())
    if '.dynamic' not in sections: return []
    header, body = sections['.dynamic']; link = header[6]
    require(link < len(entries) and len(body) % 16 == 0, 'Invalid ELF dynamic metadata')
    strings = entries[link]; data = Path(path).read_bytes()[strings[4]:strings[4] + strings[5]]
    names = []
    for offset in range(0, len(body), 16):
        tag, value = struct.unpack_from('<QQ', body, offset)
        if tag == 1:
            end = data.find(b'\0', value); require(0 <= value < len(data) and end >= value, 'Invalid ELF library name')
            name = data[value:end].decode('ascii'); require(name in LIBRARIES, 'Unapproved guest runtime library')
            names.append(name)
    return names


def worker_runtime(worker):
    worker = Path(worker).resolve(strict=True)
    loader = readiness.elf_interpreter(worker)
    require(str(loader) == '/lib64/ld-linux-x86-64.so.2', 'Only reviewed GNU x86_64 worker interpreter is supported')
    files = {'lib64/ld-linux-x86-64.so.2': loader.resolve(strict=True)}
    pending, done = needed_libraries(worker), set()
    while pending:
        name = pending.pop()
        if name in done: continue
        require(name in LIBRARIES, 'Unapproved worker dependency')
        candidate = next((p for p in (Path('/lib/x86_64-linux-gnu') / name, Path('/usr/lib/x86_64-linux-gnu') / name) if p.is_file()), None)
        require(candidate is not None, 'Reviewed worker runtime dependency missing')
        resolved = candidate.resolve(strict=True)
        require(resolved.parent in (Path('/usr/lib/x86_64-linux-gnu'), Path('/lib/x86_64-linux-gnu')), 'Runtime library escaped system namespace')
        files['lib/x86_64-linux-gnu/' + name] = resolved
        done.add(name); pending.extend(needed_libraries(resolved))
    require(len(files) <= 8 and sum(p.stat().st_size for p in files.values()) < 16 * 1024 * 1024, 'Worker runtime exceeds fixture budget')
    return files


def route_guard_program():
    """One awk parser shared by guest execution and unprivileged table fixtures."""
    return '''
function fail() { invalid=1 }
function hex(s, n,i,c,v) {
 if (length(s)<1 || length(s)>8 || s !~ /^[0-9A-Fa-f]+$/) { fail(); return 0 }
 n=0
 for(i=1;i<=length(s);i++) { c=tolower(substr(s,i,1)); v=index("0123456789abcdef",c)-1; n=n*16+v }
 return n
}
function address(s) { return length(s)==32 && s ~ /^[0-9A-Fa-f]+$/ }
FILENAME==ARGV[1] {
 if(FNR==1) { if($1!="Iface" || $2!="Destination" || $3!="Gateway" || $8!="Mask") fail(); header++; next }
 if(NF!=11) { fail(); next }
 if($2=="00000000" && $8=="00000000") defaults4++
 if($1=="eth0" && toupper($2)=="00004D0A" && $3=="00000000" && toupper($8)=="FCFFFFFF" && hex($4)==1) connected++
 else fail()
 next
}
FILENAME==ARGV[2] {
 if(NF!=10 || !address($1) || !address($3) || !address($5) || ($10!="lo" && $10!="eth0")) { fail(); next }
 flags=hex($9); prefix=hex($2)
 if(prefix>128) fail()
 if($1=="00000000000000000000000000000000" && prefix==0) {
  up=int(flags/1)%2; rejected=int(flags/512)%2
  if(rejected) sentinels++
  else if(up) defaults6++
 }
 next
}
END {
 if(invalid || header!=1 || connected!=1 || defaults4!=0 || defaults6!=0 || sentinels>8) exit 42
 printf "{\\"ipv4_connected_routes\\":%d,\\"ipv4_default_routes\\":%d,\\"ipv6_default_routes\\":%d,\\"ipv6_reject_sentinels\\":%d}",connected,defaults4,defaults6,sentinels
}
'''


def guest_init(modules):
    loads = '\n'.join('insmod /modules/' + path.name + ' || fatal module_load' for path in modules)
    return ('''#!/bin/sh
# This generated script is exclusively a guest PID1; never execute on host.
[ "$$" -eq 1 ] || exit 97
ulimit -c 0
/bin/busybox --install -s /bin
fatal() { echo "DEVDROP_GUEST_FATAL $1"; poweroff -f; exit 98; }
mount -t proc proc /proc || fatal proc_mount
mount -t sysfs sysfs /sys || fatal sys_mount
mount -t devtmpfs devtmpfs /dev || fatal dev_mount
exec </dev/ttyS0 >/dev/ttyS0 2>&1
stty -echo -icanon min 1 time 0 || fatal console_mode
mount -t tmpfs -o mode=0700 tmpfs /run || fatal run_mount
devdrop_guest=unknown
for word in $(cat /proc/cmdline); do case "$word" in devdrop_guest=*) devdrop_guest=${word#*=};; esac; done
case "$devdrop_guest" in devdrop-a) role=a; address=10.77.0.1;; devdrop-b) role=b; address=10.77.0.2;; *) fatal role;; esac
''' + loads + '''
count=0
while [ ! -b /dev/vda ]; do count=$((count+1)); [ "$count" -lt 100 ] || fatal disk_missing; sleep 0.1; done
mount -t ext4 -o noatime /dev/vda /state || fatal fixture_mount
if [ ! -e /state/devdrop-fixture-kind ]; then
 printf 'devdrop-isolated-vm-fixture-v1\\n' > /state/devdrop-fixture-kind || fatal marker
 mkdir -m 0700 /state/devdrop-fixture || fatal fixture_dir
 sync
fi
[ "$(cat /state/devdrop-fixture-kind)" = devdrop-isolated-vm-fixture-v1 ] || fatal marker
[ "$(ls /sys/class/net | sort | tr '\\n' ' ')" = 'eth0 lo ' ] || fatal interfaces
ip link set lo up || fatal loopback
ip addr add "$address/30" dev eth0 || fatal address
ip link set eth0 up || fatal link
route_summary=$(awk 'REPLACE_ROUTE_GUARD' /proc/net/route /proc/net/ipv6_route) || fatal route_guard
[ ! -e /etc/resolv.conf ] || fatal resolver
boot=$(sha256sum /proc/sys/kernel/random/boot_id | cut -d' ' -f1)
printf 'DEVDROP_VM_READY {"guest":"%s","kernel":"%s","boot_id_sha256":"%s","address":"%s/30","interfaces":["eth0","lo"],"default_routes":0,"dns_configured":false,"routes":%s}\\n' "$devdrop_guest" "$(uname -r)" "$boot" "$address" "$route_summary"
mkfifo -m 0600 /run/worker.in /run/worker.out || fatal fifo
exec 3<>/run/worker.in
exec 4<>/run/worker.out
while IFS= read -r line; do printf 'DEVDROP_WORKER %s\\n' "$line"; done <&4 &
relay_pid=$!
worker_pid=
start_worker() {
 [ -z "$worker_pid" ] || { echo 'DEVDROP_SUPERVISOR {"reply":"refused"}'; return; }
 DEVDROP_VM_FIXTURE=1 /bin/vm_peer "$role" <&3 >&4 2>/run/worker.stderr &
 worker_pid=$!
}
start_worker
while IFS= read -r control; do
 case "$control" in
  'worker '*) printf '%s\\n' "${control#worker }" >&3;;
  nic_down) ip link set eth0 down || fatal link_down; printf 'DEVDROP_SUPERVISOR {"reply":"nic_down","worker_pid":%s,"boot_id_sha256":"%s","operstate":"%s"}\\n' "$worker_pid" "$boot" "$(cat /sys/class/net/eth0/operstate)";;
  nic_up) ip link set eth0 up || fatal link_up; printf 'DEVDROP_SUPERVISOR {"reply":"nic_up","worker_pid":%s,"boot_id_sha256":"%s","operstate":"%s"}\\n' "$worker_pid" "$boot" "$(cat /sys/class/net/eth0/operstate)";;
  kill_worker) [ -n "$worker_pid" ] || fatal no_worker; kill -KILL "$worker_pid" || fatal worker_kill; wait "$worker_pid" 2>/dev/null; worker_pid=; echo 'DEVDROP_SUPERVISOR {"reply":"worker_killed"}';;
  start_worker) start_worker;;
  reboot) sync; reboot -f;;
  poweroff) sync; poweroff -f;;
  *) echo 'DEVDROP_SUPERVISOR {"reply":"refused"}';;
 esac
done
poweroff -f
''').replace('REPLACE_ROUTE_GUARD', route_guard_program()).encode('ascii')


def archive(entries):
    data = bytearray(); seen = set()
    for inode, (name, mode, body, major, minor) in enumerate(entries + [('TRAILER!!!', 0, b'', 0, 0)], 1):
        require(name not in seen and (name == '.' or (not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/')))), 'Unsafe initrd entry')
        seen.add(name); filename = name.encode('ascii') + b'\0'
        fields = [inode, mode, 0, 0, 1, 0, len(body), 0, 0, major, minor, len(filename), 0]
        data += b'070701' + b''.join(f'{value:08x}'.encode() for value in fields) + filename
        data += b'\0' * (-len(data) % 4); data += body; data += b'\0' * (-len(data) % 4)
    require(len(data) < 160 * 1024 * 1024, 'Initrd exceeds fixture budget')
    return gzip.compress(bytes(data), mtime=0)


def initrd_image(busybox, worker, modules, runtime):
    directories = {'.', 'bin', 'dev', 'proc', 'sys', 'tmp', 'run', 'state', 'modules', 'lib', 'lib64', 'lib/x86_64-linux-gnu'}
    entries = [(name, 0o040755, b'', 0, 0) for name in sorted(directories, key=lambda n: (n.count('/'), n))]
    entries += [('dev/console', 0o020600, b'', 5, 1), ('bin/busybox', 0o100755, Path(busybox).read_bytes(), 0, 0),
                ('bin/sh', 0o120777, b'busybox', 0, 0), ('bin/vm_peer', 0o100755, Path(worker).read_bytes(), 0, 0),
                ('init', 0o100755, guest_init(modules), 0, 0)]
    entries += [('modules/' + p.name, 0o100644, p.read_bytes(), 0, 0) for p in modules]
    entries += [(name, 0o100755, path.read_bytes(), 0, 0) for name, path in runtime.items()]
    return archive(entries)


def create_disk(root, name):
    root = Path(root).resolve(strict=True)
    require(name in ('a', 'b'), 'Unknown fixture disk role')
    path = root / ('fixture-' + name + '.img')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try: os.ftruncate(fd, 64 * 1024 * 1024)
    finally: os.close(fd)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == 64 * 1024 * 1024 and path.parent == root, 'Only a new generated regular fixture disk may be formatted')
    require(Path('/usr/sbin/mkfs.ext4').is_file(), 'Existing official e2fsprogs formatter unavailable')
    command(['/usr/sbin/mkfs.ext4', '-F', '-q', '-m', '0', '-E', 'lazy_itable_init=0,lazy_journal_init=0', str(path)], timeout=60, limit=4096)
    return path


def qemu_args(binary, bios, kernel, initrd, role, data_dir, disk, cable_fd):
    require(role in ('a', 'b') and isinstance(cable_fd, int) and cable_fd > 2, 'Invalid fixed guest/cable identity')
    require(',' not in str(disk) and Path(disk).suffix == '.img', 'Unsafe generated disk argument')
    base = readiness.qemu_args(binary, bios, kernel, initrd, 'devdrop-' + role, data_dir)
    at = base.index('-nic'); del base[at:at + 2]
    # Direct -kernel boot needs no PXE expansion ROM. QEMU6.2 otherwise requests
    # efi-virtio.rom from an optional package absent in download-only setup.
    base += ['-netdev', f'socket,id=lab,fd={cable_fd}', '-device', 'virtio-net-pci,netdev=lab,romfile=,mac=52:54:00:77:00:0' + ('1' if role == 'a' else '2'),
             '-drive', f'file={disk},format=raw,if=none,id=fixture,cache=none', '-device', 'virtio-blk-pci,drive=fixture']
    base[base.index('-append') + 1] += ' devdrop_vm_fixture=1 oops=panic'
    return base


class Guest:
    def __init__(self, args, environment, cable_fd, deadline):
        self.proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     env=environment, pass_fds=(cable_fd,), start_new_session=True)
        try:
            self.selector = selectors.DefaultSelector(); self.selector.register(self.proc.stdout, selectors.EVENT_READ)
            os.set_blocking(self.proc.stdin.fileno(), False)
        except Exception:
            self.proc.kill(); self.proc.wait(timeout=8)
            self.proc.stdin.close(); self.proc.stdout.close()
            raise
        self.buffer = b''; self.total = 0; self.deadline = deadline; self.events = []; self.milestones = []; self.qemu_categories = []

    def diagnostic(self):
        return dict(console_bytes=self.total, boot_milestones=self.milestones, qemu_categories=self.qemu_categories, returncode=self.proc.poll())

    def event(self, prefix, timeout=120):
        end = min(self.deadline, time.monotonic() + timeout)
        while time.monotonic() < end:
            for i, (tag, record) in enumerate(self.events):
                if tag == prefix: self.events.pop(i); return record
            while b'\n' in self.buffer:
                line, self.buffer = self.buffer.split(b'\n', 1)
                require(len(line) <= 65536, 'Guest line exceeds bounded control budget')
                for milestone in (b'Linux version', b'Run /init', b'Kernel panic', b'Could not load option rom', b'Initramfs unpacking failed'):
                    if milestone in line and milestone.decode() not in self.milestones: self.milestones.append(milestone.decode())
                for category, patterns in (
                    ('missing_guest_option_rom', (b'failed to find romfile', b'Could not open option rom', b'Could not load option rom')),
                    ('invalid_inherited_socket', (b'not a socket', b'Bad file descriptor', b'could not open socket')),
                    ('guest_device_unavailable', (b'not a valid device model name', b'failed to initialize', b'Could not open backing file')),
                ):
                    if any(pattern in line for pattern in patterns) and category not in self.qemu_categories: self.qemu_categories.append(category)
                for tag in ('DEVDROP_VM_READY', 'DEVDROP_WORKER', 'DEVDROP_SUPERVISOR'):
                    marker = (tag + ' ').encode()
                    if line.startswith(marker):
                        record = json.loads(line[len(marker):]); require(isinstance(record, dict), 'Invalid public guest record')
                        self.events.append((tag, record))
                if line.startswith(b'DEVDROP_GUEST_FATAL '):
                    stage = line.split(b' ', 1)[1].strip().decode('ascii')
                    require(stage in ('proc_mount', 'sys_mount', 'dev_mount', 'console_mode', 'run_mount', 'role', 'module_load', 'disk_missing', 'fixture_mount', 'marker', 'fixture_dir', 'interfaces', 'loopback', 'address', 'link', 'route_guard', 'resolver', 'fifo', 'link_down', 'link_up', 'no_worker', 'worker_kill'), 'Unrecognized guest failure stage')
                    raise RuntimeError('Guest fixed stage failed: ' + stage)
            if self.selector.select(min(.2, max(0, end - time.monotonic()))):
                chunk = os.read(self.proc.stdout.fileno(), 65536)
                require(bool(chunk), 'Owned guest console closed; diagnostics=' + json.dumps(self.diagnostic(), sort_keys=True))
                self.total += len(chunk); require(self.total <= 4 * 1024 * 1024, 'Guest console exceeds metadata budget')
                self.buffer += chunk
            elif self.proc.poll() is not None:
                raise RuntimeError('Owned guest exited; diagnostics=' + json.dumps(self.diagnostic(), sort_keys=True))
        stage = {'DEVDROP_VM_READY': 'boot_modules_disk_network', 'DEVDROP_WORKER': 'worker_protocol', 'DEVDROP_SUPERVISOR': 'fixed_supervisor'}[prefix]
        raise RuntimeError('Bounded guest response deadline exceeded; stage=' + stage + '; console_bytes=' + str(self.total) + '; boot_milestones=' + json.dumps(self.milestones))

    def write(self, line):
        require(time.monotonic() < self.deadline and '\n' not in line and len(line.encode()) <= 65536, 'Invalid or expired guest control')
        remaining = memoryview((line + '\n').encode()); end = min(self.deadline, time.monotonic() + 10)
        with selectors.DefaultSelector() as selector:
            selector.register(self.proc.stdin, selectors.EVENT_WRITE)
            while remaining:
                require(time.monotonic() < end and self.proc.poll() is None, 'Bounded guest control write failed')
                if selector.select(min(.1, max(0, end - time.monotonic()))):
                    try: remaining = remaining[os.write(self.proc.stdin.fileno(), remaining):]
                    except BlockingIOError: pass

    def supervisor(self, action, reply=True):
        require(action in ('nic_down', 'nic_up', 'kill_worker', 'start_worker', 'reboot', 'poweroff'), 'Unrecognized supervisor action')
        self.write(action)
        if reply: return self.event('DEVDROP_SUPERVISOR')

    def worker(self, request, reply=True):
        require(isinstance(request, dict) and request.get('command') in ('pair', 'listen', 'arm', 'wait', 'send', 'retry', 'status', 'review', 'tamper_hash', 'delete_outside_scope', 'sequence_quota'), 'Unrecognized worker command')
        self.write('worker ' + json.dumps(request, separators=(',', ':')))
        if reply: return self.event('DEVDROP_WORKER')

    def close(self):
        if self.proc.poll() is None:
            try:
                os.write(self.proc.stdin.fileno(), b'poweroff\n'); self.proc.wait(timeout=8)
            except (OSError, subprocess.TimeoutExpired): self.proc.kill(); self.proc.wait(timeout=8)
        require(self.proc.poll() is not None, 'Owned QEMU process cleanup uncertain')
        self.selector.close()
        self.proc.stdin.close(); self.proc.stdout.close()


def ci_context(output, worker):
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted' and os.environ.get('DEVDROP_PUBLIC_REPOSITORY') == 'true', 'Approved public hosted CI required')
    require(os.environ.get('GITHUB_REPOSITORY') == 'Rickythegreat1/dropdev' and os.environ.get('GITHUB_JOB') == 'isolated_transport', 'Unexpected repository/job')
    require(os.uname().machine == 'x86_64', 'Reviewed x86_64 fixture required')
    release = __import__('platform').freedesktop_os_release()
    require(release.get('ID') == 'ubuntu' and release.get('VERSION_ID') == '22.04', 'Reviewed Ubuntu22.04 host required')
    temp = Path(os.environ['RUNNER_TEMP']).resolve(strict=True); output = Path(output).absolute()
    require(str(temp).startswith('/home/runner/work/') and output == temp / 'devdrop-isolated-vm-transport.json' and not output.exists() and not output.is_symlink(), 'Exact new CI proof path required')
    workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
    require(Path(worker).absolute() == workspace / 'target/release/examples/vm_peer' and Path(worker).is_file() and not Path(worker).is_symlink(), 'Exact own compiled fixture worker required')
    require(re.fullmatch('[0-9a-f]{40}', os.environ.get('GITHUB_SHA', '')) is not None, 'Exact source commit required')
    return temp, output


def official_setup(root):
    """Reuse reviewed signed APT download/extraction pattern, never install hooks."""
    debs = root / 'debs'; debs.mkdir(mode=0o755); tools = root / 'tools'; tools.mkdir()
    command(['sudo', '-n', 'apt-get', 'update'], timeout=240)
    simulation = command(['apt-get', '--simulate', '--no-install-recommends', '--assume-yes', 'install', 'qemu-system-x86', 'busybox-static'], timeout=60)
    requested = {name: version for name, version in re.findall(r'^Inst ([a-z0-9.+:-]+)(?: \[[^\]]+\])? \(([^ ]+)', simulation, re.MULTILINE)}
    for name in ('qemu-system-x86', 'qemu-system-common', 'qemu-system-data', 'seabios', 'busybox-static'):
        metadata = command(['apt-cache', 'show', '--no-all-versions', name]); match = re.search(r'^Version: (\S+)$', metadata, re.MULTILINE)
        require(match is not None, 'Official package version missing'); requested.setdefault(name, match.group(1))
    depends = command(['apt-cache', 'depends', 'linux-image-virtual'])
    candidates = set(re.findall(r'Depends:\s+(linux-image-[0-9][a-zA-Z0-9.+-]+)', depends))
    require(len(candidates) == 1, 'Official virtual kernel not unique')
    kernel_name = candidates.pop(); module_name = kernel_name.replace('linux-image-', 'linux-modules-', 1)
    for name in (kernel_name, module_name):
        match = re.search(r'^Version: (\S+)$', command(['apt-cache', 'show', '--no-all-versions', name]), re.MULTILINE)
        require(match is not None, 'Matching official image/modules unavailable'); requested[name] = match.group(1)
    require(0 < len(requested) <= 130, 'Official dependency closure exceeds budget')
    command(['apt-get', 'download'] + [f'{name}={version}' for name, version in requested.items()], cwd=debs, timeout=300)
    packages = []
    for deb in sorted(debs.glob('*.deb')):
        name = command(['dpkg-deb', '--field', str(deb), 'Package']).strip(); version = command(['dpkg-deb', '--field', str(deb), 'Version']).strip()
        require(name in {p.split(':')[0] for p in requested} and len(version) < 128, 'Unexpected official package metadata')
        packages.append(dict(package=name, version=version, sha256=sha(deb)))
        command(['dpkg-deb', '--extract', str(deb), str(tools)])
    kernels = list((tools / 'boot').glob('vmlinuz-*')); require(len(kernels) == 1, 'Expected one official guest kernel')
    release = kernels[0].name.removeprefix('vmlinuz-'); require(module_name == 'linux-modules-' + release, 'Kernel/modules version mismatch')
    modules = module_closure(tools / 'lib/modules' / release)
    busybox = tools / 'bin/busybox'
    if not busybox.is_file(): busybox = tools / 'usr/bin/busybox'
    readiness.static_elf(busybox)
    return tools, kernels[0], busybox, modules, packages


def run(output, worker):
    temp, output = ci_context(output, worker)
    status_before = sha('/var/lib/dpkg/status')
    result = dict(schema=SCHEMA, commit=os.environ['GITHUB_SHA'], workflow_run_id=os.environ['GITHUB_RUN_ID'],
                  github_job=os.environ['GITHUB_JOB'], topology=dict(hosts=1, guests=2, vcpus_each=1, ram_mib_each=512,
                  generated_disk_mib_each=64, nics_each=1, cable='inherited-AF_UNIX-SOCK_STREAM-socketpair', accelerator='QEMU TCG'),
                  transport='tls13-mutual-certificate-pin', listener='10.77.0.2:37431', admitted_sender='10.77.0.1', prefix_length=30,
                  default_routes=0, dns_configured=False, public_listener=False, host_network_changes=False,
                  production_transport=False, fixture_only=True, proposal_only=True, file_apply=False,
                  persistent_credentials=False, checks=[], identities=[], cleanup_errors=[], phase='official_tooling_setup')
    scratch_path = None; network_start = None; guests = []; cables = []
    def check(name, condition):
        require(condition, 'Fixture assertion failed: ' + name)
        result['checks'].append(dict(name=name, passed=True))
    try:
        with tempfile.TemporaryDirectory(prefix='devdrop-isolated-transport-', dir=temp) as scratch:
            scratch_path = Path(scratch); scratch_path.chmod(0o755)
            tools, kernel, busybox, modules, packages = official_setup(scratch_path)
            runtime = worker_runtime(worker)
            initrd = scratch_path / 'fixture-initrd.cpio.gz'
            initrd.write_bytes(initrd_image(busybox, worker, modules, runtime))
            disks = [create_disk(scratch_path, role) for role in ('a', 'b')]
            binary = tools / 'usr/bin/qemu-system-x86_64'; bios = tools / 'usr/share/seabios/bios-256k.bin'; data_dir = tools / 'usr/share/qemu'
            require(binary.is_file() and bios.is_file() and (data_dir / 'linuxboot_dma.bin').is_file(), 'Official extracted QEMU/BIOS/loader ROM missing')
            environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'QEMU_MODULE_DIR': str(tools / 'usr/lib/x86_64-linux-gnu/qemu')}
            paths = [tools / 'usr/lib/x86_64-linux-gnu', tools / 'lib/x86_64-linux-gnu', tools / 'usr/lib', tools / 'lib']
            prefix = [str(readiness.elf_interpreter(binary)), '--library-path', ':'.join(map(str, paths))]
            version = command(prefix + [str(binary), '--version'], environment=environment, timeout=10, limit=4096)
            result.update(qemu_version=version.splitlines()[0], packages=packages, guest_kernel=kernel.name.removeprefix('vmlinuz-'),
                          kernel_sha256=sha(kernel), initrd_sha256=sha(initrd), worker_sha256=sha(worker),
                          modules=[dict(name=p.name, sha256=sha(p)) for p in modules],
                          guest_runtime=[dict(name=name, sha256=sha(path)) for name, path in runtime.items()])
            network_start = time.monotonic()
            # Reserve one full minute for owned-process termination, wait and FD
            # closure, inside the approved thirty-minute maximum cable lifetime.
            deadline = network_start + 1740
            try:
                cables = list(socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM))
                require(all(s.family == socket.AF_UNIX and s.type == socket.SOCK_STREAM for s in cables), 'Only a Unix socketpair cable is approved')
                result['phase'] = 'qemu_launch'
                for i, role in enumerate(('a', 'b')):
                    info = disks[i].lstat()
                    require(disks[i].parent == scratch_path and stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == 64 * 1024 * 1024, 'Generated regular disk changed before guest launch')
                    args = prefix + qemu_args(binary, bios, kernel, initrd, role, data_dir, disks[i], cables[i].fileno())
                    guests.append(Guest(args, environment, cables[i].fileno(), deadline))
                # Both QEMUs now own their sole respective endpoint. Closing the
                # parent's copies prevents an invisible extra cable owner.
                for cable in cables: cable.close()
                a, b = guests
                result['phase'] = 'guest_boot'
                boots = [validate_boot(g.event('DEVDROP_VM_READY'), role, result['guest_kernel']) for g, role in zip(guests, ('a', 'b'))]
                result['initial_boots'] = boots
                check('two_actual_guest_kernels_independent_boot_ids', boots[0]['boot_id_sha256'] != boots[1]['boot_id_sha256'])
                result['phase'] = 'worker_startup'
                offers = [worker_offer(g.event('DEVDROP_WORKER'), role, 'initial', result) for g, role in zip(guests, ('a', 'b'))]
                check('initial_generated_queues_empty_no_workspace', status(a)['pending'] == 0 and status(b)['pending'] == 0)
                check('unpaired_send_refused_before_transport', a.worker(dict(command='send')) == dict(reply='failure', failure_class='invalid_control_or_state'))
                result['phase'] = 'initial_pairing_transfer'
                pairing = pair(a, b, *offers)
                check('explicit_both_end_fingerprint_pairing', HEX.fullmatch(pairing) is not None)
                listen(b)
                for fault, name in [('tamper_hash', 'actual_tls_payload_hash_tamper_rejected'), ('delete_outside_scope', 'actual_tls_delete_scope_rejected'), ('sequence_quota', 'actual_tls_sequence_quota_rejected')]:
                    sent, served = exchange(a, b, fault)
                    check(name, not sent['ok'] and not served['ok'] and status(b)['pending'] == 0)
                sent, served = exchange(a, b, 'send')
                first = valid_receipt(sent, served, pairing, 'queued', 1)
                first_review = review(b, first)
                check('actual_cross_guest_mutual_tls_proposal_queued', status(b)['pending'] == 1)
                sent, served = exchange(a, b, 'retry'); valid_receipt(sent, served, pairing, 'duplicate', 1)
                check('exact_retry_idempotent_single_durable_proposal', status(b)['pending'] == 1)
                result['phase'] = 'nic_interruption'
                down = b.supervisor('nic_down')
                require(down == dict(reply='nic_down', worker_pid=offers[1]['pid'], boot_id_sha256=boots[1]['boot_id_sha256'], operstate='down'), 'NIC down did not verify same worker/kernel')
                sent, served = exchange(a, b, 'retry')
                check('actual_guest_nic_down_refuses_transfer_without_worker_restart', not sent['ok'] and not served['ok'] and status(b)['pending'] == 1)
                up = b.supervisor('nic_up')
                require(up.get('reply') == 'nic_up' and up.get('worker_pid') == offers[1]['pid'] and up.get('boot_id_sha256') == boots[1]['boot_id_sha256'] and up.get('operstate') in ('up', 'unknown'), 'NIC up did not verify same worker/kernel')
                sent, served = exchange(a, b, 'retry'); valid_receipt(sent, served, pairing, 'duplicate', 1)
                check('nic_up_recovers_same_pairing_exact_duplicate', status(b)['pending'] == 1)
                result['nic_cycle'] = [down, up]
                result['phase'] = 'worker_hard_kill_recovery'
                restart(b)
                b2 = worker_offer(b.event('DEVDROP_WORKER'), 'b', 'after_hard_kill', result)
                check('hard_kill_restart_keeps_queue_loses_ram_identity', b2['offer']['fingerprint'] != offers[1]['offer']['fingerprint'] and status(b)['pending'] == 1 and not status(b)['paired'])
                one_pair = b.worker(dict(command='pair', remote=offers[0]['offer'], confirmed_fingerprint=offers[0]['offer']['fingerprint'], scope=SCOPE))
                require(one_pair.get('reply') == 'paired', 'One-sided negative pairing could not be prepared')
                listen(b)
                sent, served = exchange(a, b, 'retry')
                check('old_sender_pin_refuses_restarted_receiver', not sent['ok'] and not served['ok'] and sent['failure_class'] in ('server_tls', 'certificate_pin') and status(b)['pending'] == 1)
                restart(a); restart(b)
                a2 = worker_offer(a.event('DEVDROP_WORKER'), 'a', 'after_hard_kill', result)
                b3 = worker_offer(b.event('DEVDROP_WORKER'), 'b', 'after_second_hard_kill', result)
                check('sender_ram_outbox_lost_on_real_process_kill', not status(a)['has_outbox'] and not status(a)['paired'])
                pair2 = pair(a, b, a2, b3); require(pair2 != pairing, 'Fresh RAM pairing unexpectedly reused old grant')
                listen(b); sent, served = exchange(a, b, 'send'); valid_receipt(sent, served, pair2, 'queued', 1)
                check('fresh_explicit_pairing_after_process_restart_queues_new_proposal', status(b)['pending'] == 2)
                result['phase'] = 'guest_kernel_reboot_recovery'
                old_emulator_pid = b.proc.pid
                b.supervisor('reboot', reply=False)
                reboot = validate_boot(b.event('DEVDROP_VM_READY'), 'b', result['guest_kernel'])
                b4 = worker_offer(b.event('DEVDROP_WORKER'), 'b', 'after_kernel_reboot', result)
                check('actual_guest_kernel_reboot_same_emulator_new_boot_id', b.proc.pid == old_emulator_pid and reboot['boot_id_sha256'] not in {boot['boot_id_sha256'] for boot in boots})
                check('persistent_proposals_recover_after_kernel_reboot', status(b)['pending'] == 2 and not status(b)['paired'] and review(b, first) == first_review)
                check('kernel_reboot_discards_private_ram_identity', b4['offer']['fingerprint'] != b3['offer']['fingerprint'])
                restart(a); a3 = worker_offer(a.event('DEVDROP_WORKER'), 'a', 'after_receiver_kernel_reboot', result)
                pair3 = pair(a, b, a3, b4); require(pair3 not in (pairing, pair2), 'Reboot pairing unexpectedly reused old grant')
                listen(b); sent, served = exchange(a, b, 'send'); valid_receipt(sent, served, pair3, 'queued', 1)
                check('fresh_both_end_pairing_required_after_kernel_reboot', status(b)['pending'] == 3)
                check('all_transfers_remain_private_proposals_no_file_apply', status(a)['workspace_absent'] and status(b)['workspace_absent'])
                result.update(receiver_reboot=reboot, queue_counts=dict(after_initial=1, after_process_restart=2, after_kernel_reboot_before_repair=2, after_kernel_reboot_repair=3))
            finally:
                result['guest_diagnostics_before_cleanup'] = [guest.diagnostic() for guest in guests]
                for guest in guests:
                    try: guest.close()
                    except Exception: result['cleanup_errors'].append('owned_qemu_stop_wait_failed')
                for cable in cables:
                    try: cable.close()
                    except Exception: result['cleanup_errors'].append('owned_cable_close_failed')
                result['network_lifetime_seconds'] = round(time.monotonic() - network_start, 3)
                result['owned_qemus_stopped'] = all(g.proc.poll() is not None for g in guests)
                result['cable_fds_closed'] = all(s.fileno() == -1 for s in cables)
                require(not result['cleanup_errors'], 'Owned fixture cleanup failed; disposable runner teardown required')
                require(result['network_lifetime_seconds'] <= 1800, 'Approved network duration exceeded')
        check('generated_disks_initrd_private_state_removed', not scratch_path.exists())
        check('owned_qemus_stopped_and_cable_descriptors_closed', result['owned_qemus_stopped'] and result['cable_fds_closed'])
        check('host_installed_package_state_unchanged', sha('/var/lib/dpkg/status') == status_before)
        result['success'] = True
    except BaseException as error:
        result['success'] = False
        result['failure_kind'] = type(error).__name__
        result['generated_private_state_removed'] = scratch_path is None or not scratch_path.exists()
        if network_start is not None: result['network_lifetime_seconds'] = round(time.monotonic() - network_start, 3)
        write_report(output, result)
        print('ISOLATED_VM_TRANSPORT_PARTIAL_EVIDENCE=' + json.dumps(result, sort_keys=True))
        raise
    result['generated_private_state_removed'] = not scratch_path.exists()
    write_report(output, result)
    print('ISOLATED_VM_TRANSPORT_EVIDENCE=' + json.dumps(result, sort_keys=True))
    return 0


def write_report(output, result):
    encoded = json.dumps(result, indent=2) + '\n'
    require(len(encoded.encode()) <= 128 * 1024, 'Sanitized fixture report exceeds evidence budget')
    with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'w') as report:
        report.write(encoded)


def validate_boot(value, role, kernel):
    require(set(value) == {'guest', 'kernel', 'boot_id_sha256', 'address', 'interfaces', 'default_routes', 'dns_configured', 'routes'}, 'Unexpected guest boot report fields')
    require(value['guest'] == 'devdrop-' + role and value['kernel'] == kernel and HEX.fullmatch(value['boot_id_sha256']) is not None, 'Guest independent kernel metadata invalid')
    require(value['address'] == ('10.77.0.1/30' if role == 'a' else '10.77.0.2/30') and value['interfaces'] == ['eth0', 'lo'] and value['default_routes'] == 0 and value['dns_configured'] is False, 'Guest network differs from approved isolated cable')
    routes = value['routes']
    require(set(routes) == {'ipv4_connected_routes', 'ipv4_default_routes', 'ipv6_default_routes', 'ipv6_reject_sentinels'} and routes['ipv4_connected_routes'] == 1 and routes['ipv4_default_routes'] == 0 and routes['ipv6_default_routes'] == 0 and type(routes['ipv6_reject_sentinels']) is int and 0 <= routes['ipv6_reject_sentinels'] <= 8, 'Guest kernel route table differs from approved isolated cable')
    return value


def worker_offer(value, role, stage, result):
    require(set(value) == {'reply', 'schema', 'pid', 'offer', 'scope'} and value['reply'] == 'offer' and value['schema'] == 'devdrop-vm-worker/v1' and value['scope'] == SCOPE, 'Unexpected fixed worker offer schema')
    require(type(value['pid']) is int and 1 < value['pid'] < 2**31, 'Invalid guest worker PID')
    offer = value['offer']
    require(set(offer) == {'certificate_der', 'fingerprint', 'nonce', 'expires_at_unix_ms'} and HEX.fullmatch(offer['fingerprint']) is not None and HEX.fullmatch(offer['nonce']) is not None, 'Invalid bounded public offer metadata')
    require(isinstance(offer['certificate_der'], list) and 64 <= len(offer['certificate_der']) <= 16384 and all(type(n) is int and 0 <= n <= 255 for n in offer['certificate_der']) and type(offer['expires_at_unix_ms']) is int, 'Invalid bounded public offer certificate')
    result['identities'].append(dict(role=role, stage=stage, guest_pid=value['pid'], fingerprint=offer['fingerprint']))
    return value


def status(guest):
    value = guest.worker(dict(command='status'))
    require(set(value) == {'reply', 'pending', 'paired', 'has_outbox', 'workspace_absent'} and value['reply'] == 'status' and type(value['pending']) is int and 0 <= value['pending'] <= 3 and all(type(value[k]) is bool for k in ('paired', 'has_outbox', 'workspace_absent')), 'Invalid fixed worker status')
    require(value['workspace_absent'], 'Fixture unexpectedly created a workspace')
    return value


def pair(a, b, a_offer, b_offer):
    values = []
    for guest, remote in ((a, b_offer['offer']), (b, a_offer['offer'])):
        value = guest.worker(dict(command='pair', remote=remote, confirmed_fingerprint=remote['fingerprint'], scope=SCOPE))
        require(set(value) == {'reply', 'pairing_id'} and value['reply'] == 'paired' and HEX.fullmatch(value['pairing_id']) is not None, 'Explicit fixture fingerprint pairing failed')
        values.append(value['pairing_id'])
    require(values[0] == values[1], 'Both guest pairing grant IDs differ')
    return values[0]


def listen(guest):
    require(guest.worker(dict(command='listen')) == dict(reply='listening', address='10.77.0.2:37431'), 'Receiver opened an unexpected listener')


def restart(guest):
    require(guest.supervisor('kill_worker') == dict(reply='worker_killed'), 'Owned guest worker hard kill failed')
    guest.supervisor('start_worker', reply=False)


def exchange(a, b, action):
    require(b.worker(dict(command='arm')) == dict(reply='armed'), 'Receiver failed to arm fixed request')
    sent = a.worker(dict(command=action)); served = b.worker(dict(command='wait'))
    for value, reply in ((sent, 'sent'), (served, 'served')):
        require(set(value) == {'reply', 'ok', 'receipt', 'failure_class'} and value['reply'] == reply and type(value['ok']) is bool, 'Invalid bounded transfer response')
        require(value['failure_class'] in (None, 'server_tls', 'certificate_pin', 'timeout_uncertain', 'request_refused'), 'Unexpected transfer failure category')
        require((value['ok'] and value['failure_class'] is None and isinstance(value['receipt'], dict)) or (not value['ok'] and value['receipt'] is None and value['failure_class'] is not None), 'Ambiguous transfer outcome')
    return sent, served


def valid_receipt(sent, served, pairing, expected_status, pending):
    require(sent['ok'] and served['ok'] and sent['receipt'] == served['receipt'], 'Authenticated guest receipts disagree')
    value = sent['receipt']
    require(set(value) == {'pairing_id', 'sequence', 'digest', 'status', 'pending_count'} and value['pairing_id'] == pairing and value['sequence'] == 1 and HEX.fullmatch(value['digest']) is not None and value['status'] == expected_status and value['pending_count'] == pending, 'Unexpected authenticated queue receipt')
    return value


def review(guest, receipt):
    value = guest.worker(dict(command='review', pairing_id=receipt['pairing_id'], sequence=1, digest=receipt['digest']))
    require(set(value) == {'reply', 'digest', 'payload_hash', 'changes'} and value['reply'] == 'reviewed' and value['digest'] == receipt['digest'] and HEX.fullmatch(value['payload_hash']) is not None and value['changes'] == 1, 'Exact generated durable proposal review failed')
    return value


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--output', required=True); parser.add_argument('--worker', required=True); args = parser.parse_args()
    def interrupted(_signum, _frame): raise RuntimeError('Disposable fixture interrupted; owned cleanup required')
    signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGINT, interrupted)
    try: raise SystemExit(run(args.output, args.worker))
    except Exception as error:
        print('ISOLATED_VM_TRANSPORT_FAILURE=' + json.dumps(dict(schema='devdrop-isolated-vm-transport-failure/v1', kind=type(error).__name__, message=str(error) if isinstance(error, RuntimeError) else 'Recognized bounded fixture operation failed', proposal_only=True)))
        raise SystemExit(1)
