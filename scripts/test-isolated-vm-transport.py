"""Pure fixture safety tests. Never boot a guest, install packages, or format disks."""
import gzip
import contextlib
import hashlib
import io
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('transport', Path(__file__).with_name('isolated-vm-transport.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class TransportSafety(unittest.TestCase):
    def test_local_execution_refused_before_any_commands_or_sockets(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}), patch.object(m, 'command') as command, patch.object(m.socket, 'socketpair') as pair:
            with self.assertRaisesRegex(RuntimeError, 'public hosted CI'): m.run('/tmp/no-proof.json', '/tmp/no-worker')
            command.assert_not_called(); pair.assert_not_called()

    def test_cable_backend_is_inherited_socket_only_and_no_host_network(self):
        args = m.qemu_args('/fixture/qemu', '/fixture/bios', '/fixture/kernel', '/fixture/initrd', 'a', '/fixture/data', '/fixture/fixture-a.img', 17)
        self.assertEqual(args[args.index('-netdev') + 1], 'socket,id=lab,fd=17')
        self.assertEqual(args[args.index('-m') + 1], '512'); self.assertEqual(args[args.index('-smp') + 1], '1')
        self.assertEqual(args[args.index('-monitor') + 1], 'none'); self.assertEqual(args[args.index('-display') + 1], 'none')
        self.assertNotIn('-nic', args)
        text = ' '.join(args)
        for forbidden in ('listen=', 'connect=', 'tap', 'bridge', 'hostfwd', 'guestfwd', 'virtfs', 'share=', 'if=ide'):
            self.assertNotIn(forbidden, text)
        self.assertIn('dump-guest-core=off', text); self.assertIn('devdrop_vm_fixture=1', text)
        self.assertIn('virtio-net-pci,netdev=lab,romfile=,mac=52:54:00:77:00:01', args)
        self.assertIn('format=raw,if=none,id=fixture,cache=none', text)
        for role, fd in [('c', 17), ('a', 2)]:
            with self.assertRaises(RuntimeError): m.qemu_args('q', 'b', 'k', 'i', role, 'd', '/fixture/a.img', fd)
        with self.assertRaises(RuntimeError): m.qemu_args('q', 'b', 'k', 'i', 'a', 'd', '/fixture/a.img,readonly=off', 17)

    def test_pid1_guard_precedes_mounts_network_and_owned_child_control(self):
        init = m.guest_init([]).decode()
        guard = init.index('[ "$$" -eq 1 ] || exit 97')
        for action in ('mount -t', 'ip addr', 'kill -KILL', 'reboot -f'):
            self.assertLess(guard, init.index(action))
        self.assertIn('ulimit -c 0', init); self.assertIn('10.77.0.1', init); self.assertIn('10.77.0.2', init)
        self.assertIn('"$address/30" dev eth0', init); self.assertIn('/proc/net/route /proc/net/ipv6_route', init)
        self.assertIn('[ ! -e /etc/resolv.conf ]', init)
        self.assertIn('DEVDROP_VM_FIXTURE=1 /bin/vm_peer "$role"', init)
        self.assertIn('devdrop-isolated-vm-fixture-v1\\n', init)
        for forbidden in ('eval ', 'sh -c', 'iptables', 'sysctl ', 'route add', 'dhcp', 'udhcpc', 'sshd', 'killall', 'pkill'):
            self.assertNotIn(forbidden, init)
        self.assertIn('worker_pid=$!', init); self.assertIn('kill -KILL "$worker_pid"', init)

    def test_archive_rejects_escape_and_duplicate_and_copies_only_fixture_files(self):
        for name in ('/etc/shadow', '../escape', 'bin/../escape', 'bin//escape'):
            with self.assertRaises(RuntimeError): m.archive([(name, 0o100600, b'fixture', 0, 0)])
        with self.assertRaises(RuntimeError): m.archive([('bin', 0o040755, b'', 0, 0)] * 2)
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / 'own-generated-placeholder'; p.write_bytes(b'fixture')
            data = gzip.decompress(m.initrd_image(p, p, [], {}))
            self.assertIn(b'bin/vm_peer\0', data); self.assertIn(b'dev/console\0', data)
            for name in (b'.ssh/', b'.aws/', b'resolv.conf', b'authorized_keys', b'PRIVATE KEY'):
                # resolv.conf is only a refusal check inside guest init, never an archive entry.
                if name == b'resolv.conf': self.assertNotIn(b'etc/resolv.conf\0', data)
                else: self.assertNotIn(name, data)

    def test_format_targets_new_regular_generated_64mib_only(self):
        original_is_file = Path.is_file
        with tempfile.TemporaryDirectory() as root, patch.object(m, 'command', return_value='') as command, patch.object(Path, 'is_file', lambda path: str(path) == '/usr/sbin/mkfs.ext4' or original_is_file(path)):
            disk = m.create_disk(root, 'a')
            self.assertEqual(disk.stat().st_size, 64 * 1024 * 1024)
            self.assertEqual(disk.stat().st_mode & 0o777, 0o600)
            self.assertEqual(command.call_args.args[0][-1], str(disk))
            self.assertEqual(command.call_args.args[0][0], '/usr/sbin/mkfs.ext4')
            with self.assertRaises(FileExistsError): m.create_disk(root, 'a')
            with self.assertRaises(RuntimeError): m.create_disk(root, '../../device')
            target = Path(root) / 'unrelated'; target.write_bytes(b'unchanged')
            (Path(root) / 'fixture-b.img').symlink_to(target)
            with self.assertRaises(FileExistsError): m.create_disk(root, 'b')
            self.assertEqual(target.read_bytes(), b'unchanged')
            self.assertEqual(command.call_count, 1)

    def test_module_closure_orders_dependencies_and_refuses_missing_cycle_link(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            for name in ('leaf', 'driver', 'built'): (root / (name + '.ko')).write_bytes(b'official-placeholder')
            (root / 'modules.builtin').write_text('kernel/built.ko\n')
            dependencies = {'driver': ['leaf', 'built'], 'leaf': []}
            with patch.object(m, 'module_dependencies', side_effect=lambda path: dependencies[path.stem]):
                self.assertEqual([p.stem for p in m.module_closure(root, ['driver'])], ['leaf', 'driver'])
                with self.assertRaisesRegex(RuntimeError, 'Missing or cyclic'): m.module_closure(root, ['missing'])
                dependencies['leaf'] = ['driver']
                with self.assertRaisesRegex(RuntimeError, 'Missing or cyclic'): m.module_closure(root, ['driver'])
            (root / 'escape.ko').symlink_to('/bin/true')
            with self.assertRaisesRegex(RuntimeError, 'escaped'): m.module_closure(root, ['driver'])

    def test_runtime_library_allowlist_refuses_openssl_or_external_paths(self):
        self.assertEqual(m.LIBRARIES, frozenset(('libc.so.6', 'libm.so.6', 'libgcc_s.so.1', 'libpthread.so.0', 'libdl.so.2', 'librt.so.1', 'ld-linux-x86-64.so.2')))
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / 'worker'; p.write_bytes(b'notELF')
            with self.assertRaisesRegex(RuntimeError, 'ELF'): m.worker_runtime(p)

    def test_serial_commands_and_deadline_refuse_before_write(self):
        guest = object.__new__(m.Guest)
        with patch.object(guest, 'write') as write:
            with self.assertRaisesRegex(RuntimeError, 'Unrecognized'): guest.supervisor('shell reboot')
            with self.assertRaisesRegex(RuntimeError, 'Unrecognized'): guest.worker({'command': 'exec', 'args': ['shell']})
            write.assert_not_called()
        guest.deadline = 0
        with self.assertRaisesRegex(RuntimeError, 'expired'): guest.write('nic_up')

    def test_socketpair_is_unix_stream_not_host_listener(self):
        # Ordinary in-process Unix sockets only; not an IP guest or transport run.
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.assertEqual(a.family, socket.AF_UNIX); self.assertEqual(a.type, socket.SOCK_STREAM)
            a.sendall(b'generated'); self.assertEqual(b.recv(16), b'generated')
        finally: a.close(); b.close()

    def test_complete_orchestration_models_per_pair_receipts_and_global_queue(self):
        with self.mocked_run() as (output, workers, _):
            self.assertEqual(m.run(output, '/fixture/worker'), 0)
            report = __import__('json').loads(output.read_text())
            self.assertTrue(report['success']); self.assertEqual(report['cleanup_errors'], [])
            self.assertEqual(report['queue_counts']['after_kernel_reboot_repair'], 3)
            self.assertEqual(len(report['identities']), 7)
            self.assertTrue(all(c['passed'] for c in report['checks']))
            self.assertTrue(all(worker.closed for worker in workers))
            self.assertTrue(report['generated_private_state_removed']); self.assertTrue(report['cable_fds_closed'])
            self.assertLess(report['network_lifetime_seconds'], 1800)
            text = output.read_text()
            for private in ('certificate_der', 'nonce', '/fixture/worker', 'PRIVATE KEY', 'generated private guest TLS fixture'):
                self.assertNotIn(private, text)

    def test_mid_scenario_failure_stops_both_guests_closes_cable_and_removes_disks(self):
        with self.mocked_run(fail_status=True) as (output, workers, cables):
            with self.assertRaisesRegex(RuntimeError, 'injected status refusal'): m.run(output, '/fixture/worker')
            report = __import__('json').loads(output.read_text())
            self.assertFalse(report['success']); self.assertTrue(report['generated_private_state_removed'])
            self.assertEqual(len(workers), 2); self.assertTrue(all(worker.closed for worker in workers))
            self.assertTrue(all(cable.fileno() == -1 for cable in cables))

    def test_second_guest_launch_failure_stops_first_and_closes_both_cable_fds(self):
        with self.mocked_run(fail_launch=True) as (output, workers, cables):
            with self.assertRaisesRegex(RuntimeError, 'injected second launch refusal'): m.run(output, '/fixture/worker')
            report = __import__('json').loads(output.read_text())
            self.assertFalse(report['success']); self.assertTrue(report['generated_private_state_removed'])
            self.assertEqual(len(workers), 1); self.assertTrue(workers[0].closed)
            self.assertEqual(len(cables), 2); self.assertTrue(all(cable.fileno() == -1 for cable in cables))

    def test_sanitized_report_refuses_dangling_symlink_or_overwrite(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / 'proof.json'; target = Path(root) / 'untouched'
            output.symlink_to(target)
            with self.assertRaises(FileExistsError): m.write_report(output, {'success': False})
            self.assertFalse(target.exists()); output.unlink()
            m.write_report(output, {'success': True})
            with self.assertRaises(FileExistsError): m.write_report(output, {'success': False})

    def test_eof_captures_only_fixed_qemu_category_not_raw_console(self):
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        guest = m.Guest([sys.executable, '-c', 'print(\'qemu: failed to find romfile "efi-virtio.rom" PRIVATE_SENTINEL\')'], {'PATH': '/usr/bin:/bin'}, a.fileno(), m.time.monotonic() + 5)
        try:
            with self.assertRaisesRegex(RuntimeError, 'missing_guest_option_rom') as failure: guest.event('DEVDROP_VM_READY', timeout=3)
            self.assertNotIn('PRIVATE_SENTINEL', str(failure.exception)); self.assertNotIn('efi-virtio.rom', str(failure.exception))
            self.assertGreater(guest.diagnostic()['console_bytes'], 0)
        finally: guest.close(); a.close(); b.close()

    def test_kernel_route_guard_accepts_only_connected_ipv4_and_ipv6_reject_sentinels(self):
        value = self.route_fixture(self.connected4(), self.reject6() * 2)
        self.assertEqual(value.returncode, 0)
        self.assertEqual(__import__('json').loads(value.stdout), dict(ipv4_connected_routes=1, ipv4_default_routes=0, ipv6_default_routes=0, ipv6_reject_sentinels=2))
        # UP+REJECT still cannot route traffic; classify separately, never count
        # the kernel sentinel as an external usable default gateway.
        self.assertEqual(self.route_fixture(self.connected4(), self.reject6().replace('00200200', '00200201')).returncode, 0)

    def test_kernel_route_guard_refuses_actual_default_gateway_foreign_net_and_malformed_rows(self):
        valid = self.connected4()
        forbidden = [valid.replace('00004D0A', '00000000').replace('FCFFFFFF', '00000000'),
                     valid.replace('00004D0A', '00004E0A'),
                     valid.replace('00000000 0001', '02004D0A 0003'),
                     valid.replace('eth0 ', 'eth1 '),
                     valid + valid.split('\n')[1] + '\n',
                     valid.split('\n')[0] + '\n']
        for table in forbidden:
            with self.subTest(table=table): self.assertEqual(self.route_fixture(table, self.reject6()).returncode, 42)
        usable6 = self.reject6().replace('00200200', '00000003').replace(' lo\n', ' eth0\n')
        self.assertEqual(self.route_fixture(valid, usable6).returncode, 42)
        self.assertEqual(self.route_fixture(valid, 'not-a-kernel-route\n').returncode, 42)

    @staticmethod
    def connected4():
        return 'Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0 00004D0A 00000000 0001 0 0 0 FCFFFFFF 0 0 0\n'

    @staticmethod
    def reject6():
        return '00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n'

    @staticmethod
    def route_fixture(ipv4, ipv6):
        with tempfile.TemporaryDirectory() as root:
            v4 = Path(root) / 'generated-route4'; v4.write_text(ipv4)
            v6 = Path(root) / 'generated-route6'; v6.write_text(ipv6)
            return subprocess.run(['awk', m.route_guard_program(), str(v4), str(v6)], capture_output=True, text=True, timeout=5)

    @contextlib.contextmanager
    def mocked_run(self, fail_status=False, fail_launch=False):
        """Exercise all orchestration with model guests, no VM/privileged tools."""
        workers, cables, durable = [], [], {}
        digest = lambda text: hashlib.sha256(text.encode()).hexdigest()
        class Process:
            pid = 1234
            def poll(self): return 0 if self.closed else None
        class ModelGuest:
            def __init__(self, args, environment, cable_fd, deadline):
                if fail_launch and workers: raise RuntimeError('injected second launch refusal')
                self.role = args[args.index('-name') + 1][-1]
                self.generation = 0; self.boot = 1; self.closed = False; self.up = True
                self.proc = Process(); self.proc.closed = False
                self.new_worker(); workers.append(self)
            def new_worker(self):
                self.generation += 1; self.paired = None; self.remote = None; self.outbox = False
                self.offer = dict(certificate_der=[1] * 64, fingerprint=digest(self.role + str(self.generation)), nonce='0' * 64, expires_at_unix_ms=123456789)
                self.pid = 100 + self.generation
            def event(self, prefix):
                if prefix == 'DEVDROP_VM_READY':
                    return dict(guest='devdrop-' + self.role, kernel='5.15.0-fixture', boot_id_sha256=digest(self.role + 'boot' + str(self.boot)), address='10.77.0.' + ('1' if self.role == 'a' else '2') + '/30', interfaces=['eth0', 'lo'], default_routes=0, dns_configured=False, routes=dict(ipv4_connected_routes=1, ipv4_default_routes=0, ipv6_default_routes=0, ipv6_reject_sentinels=2))
                return dict(reply='offer', schema='devdrop-vm-worker/v1', pid=self.pid, offer=self.offer, scope=m.SCOPE)
            def supervisor(self, action, reply=True):
                if action in ('nic_down', 'nic_up'):
                    self.up = action == 'nic_up'
                    return dict(reply=action, worker_pid=self.pid, boot_id_sha256=digest(self.role + 'boot' + str(self.boot)), operstate='up' if self.up else 'down')
                if action == 'kill_worker': return dict(reply='worker_killed')
                if action == 'start_worker': self.new_worker()
                if action == 'reboot': self.boot += 1; self.new_worker()
            def worker(self, request):
                op = request['command']
                if op == 'status':
                    if fail_status: raise RuntimeError('injected status refusal')
                    return dict(reply='status', pending=len(durable) if self.role == 'b' else 0, paired=self.paired is not None, has_outbox=self.outbox, workspace_absent=True)
                if op == 'pair':
                    self.remote = request['remote']['fingerprint']
                    self.paired = digest(''.join(sorted([self.offer['fingerprint'], self.remote])))
                    return dict(reply='paired', pairing_id=self.paired)
                if op == 'listen': return dict(reply='listening', address='10.77.0.2:37431')
                if op == 'arm': return dict(reply='armed')
                if op == 'wait': return dict(reply='served', **self.last)
                if op == 'review': return dict(reply='reviewed', digest=request['digest'], payload_hash='e' * 64, changes=1)
                if not self.paired: return dict(reply='failure', failure_class='invalid_control_or_state')
                receiver = workers[1]; self.outbox = True
                failure = None
                if not receiver.up: failure = 'timeout_uncertain'
                elif self.remote != receiver.offer['fingerprint']: failure = 'server_tls'
                elif op not in ('send', 'retry'): failure = 'request_refused'
                if failure:
                    receiver.last = dict(ok=False, receipt=None, failure_class=failure)
                else:
                    exists = self.paired in durable
                    receipt = dict(pairing_id=self.paired, sequence=1, digest=digest(self.paired + 'proposal'), status='duplicate' if exists else 'queued', pending_count=1)
                    durable[self.paired] = receipt
                    receiver.last = dict(ok=True, receipt=receipt, failure_class=None)
                return dict(reply='sent', **receiver.last)
            def close(self): self.closed = True; self.proc.closed = True
            def diagnostic(self): return dict(console_bytes=0, boot_milestones=[], qemu_categories=[], returncode=self.proc.poll())
        actual_pair = socket.socketpair
        def socketpair(*args):
            result = actual_pair(*args); cables.extend(result); return result
        def setup(root):
            tools = root / 'tools'; tools.mkdir()
            for name in ('usr/bin/qemu-system-x86_64', 'usr/share/seabios/bios-256k.bin', 'usr/share/qemu/linuxboot_dma.bin'):
                path = tools / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b'fixture')
            kernel = root / 'vmlinuz-5.15.0-fixture'; kernel.write_bytes(b'fixture')
            busybox = root / 'busybox'; busybox.write_bytes(b'fixture')
            return tools, kernel, busybox, [], []
        def disk(root, role):
            path = root / ('fixture-' + role + '.img')
            with path.open('xb') as stream: stream.truncate(64 * 1024 * 1024)
            return path
        with tempfile.TemporaryDirectory() as temp, contextlib.ExitStack() as stack:
            temp = Path(temp); output = temp / 'proof.json'
            stack.enter_context(patch.object(m, 'ci_context', return_value=(temp, output)))
            stack.enter_context(patch.object(m, 'official_setup', side_effect=setup))
            stack.enter_context(patch.object(m, 'worker_runtime', return_value={}))
            stack.enter_context(patch.object(m, 'initrd_image', return_value=b'fixture'))
            stack.enter_context(patch.object(m, 'create_disk', side_effect=disk))
            stack.enter_context(patch.object(m, 'Guest', ModelGuest))
            stack.enter_context(patch.object(m.socket, 'socketpair', side_effect=socketpair))
            stack.enter_context(patch.object(m.readiness, 'elf_interpreter', return_value=Path('/lib64/ld-linux-x86-64.so.2')))
            stack.enter_context(patch.object(m, 'command', return_value='QEMU official fixture\n'))
            original_sha = m.sha
            stack.enter_context(patch.object(m, 'sha', side_effect=lambda path: '0' * 64 if str(path) in ('/fixture/worker', '/var/lib/dpkg/status') else original_sha(path)))
            stack.enter_context(patch.dict(os.environ, {'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': '123', 'GITHUB_JOB': 'isolated_transport'}))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            yield output, workers, cables


if __name__ == '__main__': unittest.main()
