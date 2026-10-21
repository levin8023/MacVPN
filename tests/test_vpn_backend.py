"""Offline concurrency tests. No real credentials, sudo, or VPN traffic required."""
import fcntl
import errno
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from strongvpn import connection_config, connection_names, safe_environment
from vpn_backend import Backend, ControlHandler, ControlServer, EndpointRoutes, RouteGuard, StrongSwanEngine, atomic_json, parse_sa, rpc, wait_backend_stopped


def configurations():
    return {name: dict(profile=name, label=name, server=server, group='test-group',
                       user='test-user', password='test-password', shared_secret=b'test-psk')
            for name, server in [('one', '192.0.2.1'), ('two', '192.0.2.2')]}


class FakeEngine:
    def __init__(self):
        self.lock = threading.Lock()
        self.alive = False
        self.starts = 0
        self.installed = set()
        self.calls = []
        self.failures = {}
        self.auth_failures = set()
        self.started = {name: threading.Event() for name in configurations()}
        self.gates = {}
        self.terminate_failures = set()

    def start(self):
        with self.lock:
            self.alive = True
            self.starts += 1

    def stop(self):
        with self.lock:
            self.alive = False
            self.installed.clear()
        for gate in self.gates.values():
            gate.set()

    def healthy(self):
        return self.alive

    def status(self, profile):
        with self.lock:
            installed = profile in self.installed
        return dict(installed=installed, virtual_ips=['10.20.0.1'] if installed else [],
                    remote_subnets=['10.30.0.0/24'] if installed else [])

    def initiate(self, profile, timeout):
        with self.lock:
            self.calls.append(profile)
        self.started[profile].set()
        if profile in self.gates:
            self.gates[profile].wait(2)
        with self.lock:
            if profile in self.auth_failures:
                return dict(auth_failed=True, success=False)
            if self.failures.get(profile, 0):
                self.failures[profile] -= 1
                return dict(auth_failed=False, success=False)
            if self.alive:
                self.installed.add(profile)
        return dict(auth_failed=False, success=True)

    def terminate(self, profile):
        with self.lock:
            if profile in self.terminate_failures:
                raise RuntimeError('Synthetic termination failure')
            self.installed.discard(profile)


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='macvpn-test-')
        self.root = Path(self.temp.name)
        self.engine = FakeEngine()
        self.backend = Backend(configurations(), self.root, self.root / 'status.json',
                               self.root / 'config.json', engine=self.engine,
                               poll_interval=0.02, retry_interval=0.03)
        self.backend.start()

    def tearDown(self):
        self.backend.stop()
        self.temp.cleanup()

    def wait_for(self, predicate, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.01)
        self.fail('Timed out; state=' + json.dumps(self.backend.snapshot()))

    def phase(self, profile):
        return self.backend.snapshot()['profiles'][profile]['phase']

    def test_parallel_handshakes_and_disconnect_isolation(self):
        self.engine.gates['one'] = threading.Event()
        self.backend.connect('one')
        self.assertTrue(self.engine.started['one'].wait(1))
        self.backend.connect('two')
        self.wait_for(lambda: self.phase('two') == 'connected')
        self.assertEqual(self.phase('one'), 'connecting')
        self.engine.gates['one'].set()
        self.wait_for(lambda: self.phase('one') == 'connected')
        self.assertEqual(self.engine.starts, 1)
        self.backend.connect('two')
        self.assertEqual(self.engine.calls.count('two'), 1)
        self.assertTrue(self.backend.snapshot()['route_overlaps'])
        self.backend.disconnect('one')
        self.wait_for(lambda: self.phase('one') == 'disconnected')
        self.assertEqual(self.phase('two'), 'connected')
        self.assertEqual(self.engine.installed, {'two'})

    def test_auth_failure_pauses_only_selected_profile(self):
        self.engine.auth_failures.add('one')
        self.backend.connect('one')
        self.backend.connect('two')
        self.wait_for(lambda: self.phase('one') == 'auth_failed' and self.phase('two') == 'connected')
        self.assertFalse(self.backend.snapshot()['profiles']['one']['desired'])
        self.assertEqual(self.engine.calls.count('one'), 1)

    def test_initial_failure_and_later_drop_reconnect(self):
        self.engine.failures['one'] = 1
        self.backend.connect('one')
        self.wait_for(lambda: self.phase('one') == 'connected')
        self.assertEqual(self.engine.calls.count('one'), 2)
        with self.engine.lock:
            self.engine.installed.discard('one')
        self.wait_for(lambda: self.engine.calls.count('one') >= 3 and self.phase('one') == 'connected')

    def test_handshake_timeout_retries_without_affecting_other_profile(self):
        original = self.engine.initiate
        failed = []

        def initiate(profile, timeout):
            if profile == 'one' and not failed:
                failed.append(True)
                raise TimeoutError('Synthetic stalled handshake')
            return original(profile, timeout)

        self.engine.initiate = initiate
        self.backend.connect('two')
        self.wait_for(lambda: self.phase('two') == 'connected')
        self.backend.connect('one')
        self.wait_for(lambda: self.phase('one') == 'connected')
        self.assertEqual(self.engine.calls.count('two'), 1)
        self.assertEqual(self.phase('two'), 'connected')

    def test_control_failure_respects_disabled_reconnect(self):
        def initiate(profile, timeout):
            raise TimeoutError('Synthetic stalled handshake')
        self.engine.initiate = initiate
        self.backend.connect('one', auto_reconnect=False)
        self.wait_for(lambda: self.phase('one') == 'failed')
        self.assertFalse(self.backend.snapshot()['profiles']['one']['desired'])

    def test_disk_full_status_cache_does_not_stop_reconnect_or_peer(self):
        with patch('vpn_backend.atomic_json', side_effect=OSError(errno.ENOSPC, 'Synthetic disk full')):
            self.backend.connect('one')
            self.backend.connect('two')
            self.wait_for(lambda: self.phase('one') == self.phase('two') == 'connected')
            self.assertIsNotNone(self.backend.snapshot()['storage_error'])
            with self.engine.lock:
                self.engine.installed.discard('one')
            self.wait_for(lambda: self.engine.calls.count('one') >= 2 and self.phase('one') == 'connected')
            self.assertEqual(self.engine.calls.count('two'), 1)
            self.assertTrue(all(worker.is_alive() for worker in self.backend.workers.values()))
        self.backend.publish()
        self.assertIsNone(self.backend.snapshot()['storage_error'])
        self.assertTrue((self.root / 'status.json').exists())

    def test_disk_full_error_handler_and_log_write_do_not_kill_worker(self):
        original = self.engine.status
        failed = []
        def status(profile):
            if profile == 'one' and not failed:
                failed.append(True)
                raise RuntimeError('Synthetic control failure')
            return original(profile)
        self.engine.status = status
        with patch('vpn_backend.os.open', side_effect=OSError(errno.ENOSPC, 'Synthetic disk full')):
            self.backend.log('one', 'Synthetic diagnostic')
            self.backend.connect('one')
            self.wait_for(lambda: self.phase('one') == 'connected')
            self.assertTrue(self.backend.workers['one'].is_alive())
            self.assertIsNotNone(self.backend.snapshot()['storage_error'])
        self.backend.log('one', 'Storage recovered')
        self.backend.publish()
        self.assertIsNone(self.backend.snapshot()['storage_error'])

    def test_log_rotation_is_bounded_and_keeps_redaction(self):
        self.backend.log_max_bytes = 1
        for _ in range(5):
            self.backend.log('one', 'Synthetic test-user test-password test-psk')
        for name in ('strongvpn-backend.log', 'strongvpn-one.log'):
            paths = list(self.root.glob(name + '*'))
            self.assertEqual(len(paths), 3)
            for path in paths:
                text = path.read_text()
                self.assertNotIn('test-password', text)
                self.assertNotIn('test-psk', text)
                self.assertIn('[REDACTED]', text)

    def test_monitor_recovers_exited_worker_without_restarting_peer_or_engine(self):
        self.backend.connect('one')
        self.backend.connect('two')
        self.wait_for(lambda: self.phase('one') == self.phase('two') == 'connected')
        old_worker = self.backend.workers['one']
        original = self.engine.status
        exited = []
        def status(profile):
            if profile == 'one' and not exited:
                exited.append(True)
                # Escape the ordinary per-iteration Exception handler.
                raise SystemExit('Synthetic worker exit')
            return original(profile)
        self.engine.status = status
        self.wait_for(lambda: self.backend.workers['one'] is not old_worker and
                      self.phase('one') == 'connected')
        self.assertEqual(self.engine.starts, 1)
        self.assertEqual(self.engine.calls.count('two'), 1)
        self.assertEqual(self.engine.calls.count('one'), 1)

    def test_disconnect_during_handshake_removes_late_tunnel(self):
        self.engine.gates['one'] = threading.Event()
        self.backend.connect('one')
        self.assertTrue(self.engine.started['one'].wait(1))
        self.backend.disconnect('one')
        self.assertEqual(self.phase('one'), 'disconnecting')
        self.engine.gates['one'].set()
        self.wait_for(lambda: self.phase('one') == 'disconnected')
        self.assertNotIn('one', self.engine.installed)

    def test_quick_disconnect_and_reconnect_does_not_lose_new_request(self):
        self.engine.gates['one'] = threading.Event()
        self.backend.connect('one')
        self.assertTrue(self.engine.started['one'].wait(1))
        self.backend.disconnect('one')
        self.backend.connect('one')
        self.engine.gates['one'].set()
        self.wait_for(lambda: self.phase('one') == 'connected')
        self.assertEqual(self.engine.calls.count('one'), 2)

    def test_failed_disconnect_is_not_reported_as_disconnected(self):
        self.backend.connect('one')
        self.wait_for(lambda: self.phase('one') == 'connected')
        self.engine.terminate_failures.add('one')
        self.backend.disconnect('one')
        self.wait_for(lambda: self.backend.snapshot()['profiles']['one']['error'] is not None)
        self.assertEqual(self.phase('one'), 'disconnecting')
        self.assertIn('one', self.engine.installed)
        self.engine.terminate_failures.clear()
        self.wait_for(lambda: self.phase('one') == 'disconnected')

    def test_engine_restart_restores_both_requested_profiles(self):
        self.backend.connect('one')
        self.backend.connect('two')
        self.wait_for(lambda: all(self.phase(name) == 'connected' for name in configurations()))
        self.engine.stop()
        self.wait_for(lambda: self.engine.starts >= 2 and
                      all(self.phase(name) == 'connected' for name in configurations()))

    def test_control_socket_whitelist_and_safe_status(self):
        server = ControlServer(str(self.root / 'control.sock'), ControlHandler)
        server.backend = self.backend
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.02})
        thread.start()
        try:
            rpc(self.root, dict(action='connect', profile='two'))
            self.wait_for(lambda: self.phase('two') == 'connected')
            state = rpc(self.root, dict(action='status'))['state']
            self.assertEqual(state['profiles']['two']['phase'], 'connected')
            with self.assertRaises(RuntimeError):
                rpc(self.root, dict(action='execute', command='anything'))
            with self.assertRaises(RuntimeError):
                rpc(self.root, dict(action='connect', profile='not-configured'))
            self.assertNotIn('test-password', json.dumps(state))
            self.assertNotIn('test-psk', json.dumps(state))
            rpc(self.root, dict(action='shutdown'))
            with self.assertRaises(RuntimeError):
                rpc(self.root, dict(action='connect', profile='one'))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_log_redacts_all_profiles(self):
        self.backend.log('one', 'test-user test-password test-psk 0sdGVzdC1wc2s=')
        text = (self.root / 'strongvpn-one.log').read_text()
        self.assertNotIn('test-user', text)
        self.assertNotIn('test-password', text)
        self.assertNotIn('test-psk', text)
        self.assertNotIn('0sdGVzdC1wc2s=', text)

    def test_disabling_reconnect_leaves_connected_tunnel_until_it_drops(self):
        self.backend.connect('one')
        self.wait_for(lambda: self.phase('one') == 'connected')
        self.backend.set_reconnect('one', False)
        self.assertIn('one', self.engine.installed)
        with self.engine.lock:
            self.engine.installed.discard('one')
        self.wait_for(lambda: self.phase('one') == 'failed')
        self.assertFalse(self.backend.snapshot()['profiles']['one']['desired'])
        self.assertEqual(self.engine.calls.count('one'), 1)

    def test_initial_failure_does_not_retry_when_disabled(self):
        self.engine.failures['one'] = 1
        self.backend.connect('one', auto_reconnect=False)
        self.wait_for(lambda: self.phase('one') == 'failed')
        self.assertEqual(self.engine.calls.count('one'), 1)

    def test_control_socket_rejects_other_user(self):
        server = ControlServer(str(self.root / 'control.sock'), ControlHandler)
        server.backend = self.backend
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.02})
        thread.start()
        try:
            with patch('vpn_backend.peer_uid', return_value=999999):
                with self.assertRaises((RuntimeError, OSError)):
                    rpc(self.root, dict(action='connect', profile='one'))
            self.assertEqual(self.engine.calls, [])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_control_error_obeys_backoff_while_other_profile_stays_connected(self):
        self.backend.retry_interval = 0.3
        self.backend.connect('two')
        self.wait_for(lambda: self.phase('two') == 'connected')
        original = self.engine.status
        calls = []

        def status(profile):
            if profile == 'one':
                calls.append(time.monotonic())
                raise TimeoutError('Synthetic control timeout')
            return original(profile)

        self.engine.status = status
        self.backend.connect('one')
        self.wait_for(lambda: len(calls) >= 3)
        self.assertGreaterEqual(calls[1] - calls[0], 0.28)
        self.assertGreaterEqual(calls[2] - calls[1], 0.58)
        self.assertEqual(self.phase('two'), 'connected')
        self.assertEqual(self.engine.calls.count('two'), 1)

    def test_unchanged_connected_state_does_not_rewrite_cache(self):
        self.backend.connect('one')
        self.wait_for(lambda: self.phase('one') == 'connected')
        with patch.object(self.backend, 'publish') as publish:
            row = self.backend.snapshot()['profiles']['one']
            self.backend.update('one', phase=row['phase'], virtual_ips=row['virtual_ips'])
            publish.assert_not_called()

    def test_runtime_diagnostics_are_private_including_old_rotations(self):
        other_root = self.root / 'private-runtime'
        other_root.mkdir()
        for name in ('status.json', 'strongvpn-backend.log.2', 'strongvpn-one.log.1', 'strongvpn-deleted.log'):
            path = other_root / name
            path.write_text('{}')
            path.chmod(0o644)
        backend = Backend(configurations(), other_root, other_root / 'status.json',
                          other_root / 'config.json', engine=FakeEngine(), poll_interval=0.02)
        try:
            backend.start()
            backend.log('one', 'Synthetic diagnostic')
            for path in other_root.iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        finally:
            backend.stop()

    def test_control_socket_bounds_slow_clients_and_recovers_slots(self):
        server = ControlServer(str(self.root / 'bounded.sock'), ControlHandler, max_clients=2)
        server.backend = self.backend
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01})
        thread.start()
        clients = []
        try:
            for _ in range(2):
                client = socket.socket(socket.AF_UNIX)
                client.settimeout(1)
                client.connect(str(self.root / 'bounded.sock'))
                client.sendall(b'{')
                clients.append(client)
            self.wait_for(lambda: server.client_slots._value == 0)
            with socket.socket(socket.AF_UNIX) as extra:
                extra.settimeout(1)
                extra.connect(str(self.root / 'bounded.sock'))
                try:
                    self.assertEqual(extra.recv(1), b'')
                except ConnectionResetError:
                    pass
            for client in clients:
                client.sendall(b'}\n')
                self.assertIn(b'"ok": false', client.recv(8192))
            self.wait_for(lambda: server.client_slots._value == 2)
            # A malformed document must not damage the server or its backend.
            self.assertFalse(self.backend.stop_event.is_set())
        finally:
            for client in clients:
                client.close()
            server.shutdown()
            server.server_close()
            thread.join()

    def test_restart_waits_for_previous_manager_cleanup(self):
        with (self.root / 'backend.lock').open('w') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            with self.assertRaises(RuntimeError):
                wait_backend_stopped(self.root, timeout=0)
            released = threading.Event()

            def cleanup():
                time.sleep(0.03)
                fcntl.flock(stream, fcntl.LOCK_UN)
                released.set()

            thread = threading.Thread(target=cleanup)
            thread.start()
            wait_backend_stopped(self.root, timeout=1)
            self.assertTrue(released.is_set())
            thread.join()


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.interface = 'utun8'
        self.gateway = '192.0.2.1'
        self.changes = []
        self.sa = dict(installed=True, virtual_ips=['192.168.16.151'], remote_subnets=['10.30.0.0/24'])
        self.guard = RouteGuard(lambda *args: None, self.run_command)

    def run_command(self, arguments, **kwargs):
        if arguments[0] == '/sbin/ifconfig':
            output = 'utun9: flags=8051 mtu 1400\n\tinet 192.168.16.151 --> 192.168.16.151 netmask 0xffffffff\n'
        elif arguments[0] == '/usr/sbin/netstat':
            output = '10.30.0 ' + self.gateway + ' USc ' + self.interface + '\n'
        elif 'change' in arguments:
            self.changes.append(arguments)
            self.interface = arguments[-1]
            output = ''
        else:
            # macOS omits the gateway field for these routes, even though
            # netstat shows the configured VPN peer as their gateway.
            output = 'destination: 10.30.0.0\nmask: 255.255.255.0\ninterface: ' + self.interface + '\n'
        return SimpleNamespace(returncode=0, stdout=output)

    def test_repairs_wrong_proxy_interface_using_vip_and_owned_route(self):
        result = self.guard.check('one', self.sa, '192.0.2.1')
        self.assertIsNone(result['route_error'])
        self.assertEqual(result['tunnel_interface'], 'utun9')
        self.assertEqual(self.changes, [['/sbin/route', '-n', 'change', '-net', '10.30.0.0/24', '-interface', 'utun9']])

    def test_correct_route_is_not_rewritten(self):
        self.interface = 'utun9'
        self.assertIsNone(self.guard.check('one', self.sa, '192.0.2.1')['route_error'])
        self.assertFalse(self.changes)

    def test_foreign_route_is_not_overwritten(self):
        self.gateway = '192.0.2.99'
        self.assertIn('owned elsewhere', self.guard.check('one', self.sa, '192.0.2.1')['route_error'])
        self.assertFalse(self.changes)

    def test_overlap_does_not_flip_route_between_vpns(self):
        self.guard.active['two'] = dict(self.sa)
        self.assertIn('Overlapping', self.guard.check('one', self.sa, '192.0.2.1')['route_error'])
        self.assertFalse(self.changes)

    def test_default_route_is_never_changed(self):
        self.sa['remote_subnets'] = ['0.0.0.0/0']
        self.assertIsNotNone(self.guard.check('one', self.sa, '192.0.2.1')['route_error'])
        self.assertFalse(self.changes)

    def test_uninstalled_tunnel_does_not_change_routes(self):
        self.sa['installed'] = False
        self.assertEqual(self.guard.check('one', self.sa, '192.0.2.1'), {})
        self.assertFalse(self.changes)

    def test_direct_endpoint_uses_default_physical_gateway_and_cleans_only_own_pin(self):
        calls = []
        interface = ['utun8']

        def runner(args, **kwargs):
            calls.append(args)
            if args[-1] == 'default':
                output = 'destination: default\ngateway: 192.168.0.1\ninterface: en0\n'
            elif 'add' in args or 'change' in args:
                interface[0] = 'en0'
                output = ''
            elif args[0] == '/usr/sbin/netstat':
                output = '192.0.2.1 192.168.0.1 UH en0\n'
            else:
                output = 'destination: 192.0.2.1\nflags: <UP,HOST' + (',STATIC' if interface[0]=='en0' else '') + '>\ninterface: ' + interface[0] + '\n'
            return SimpleNamespace(returncode=0, stdout=output)

        endpoint = EndpointRoutes(lambda *args: None, runner)
        endpoint.ensure('one', '192.0.2.1')
        endpoint.ensure('two', '192.0.2.1')
        endpoint.release('one', '192.0.2.1')
        self.assertFalse(any('delete' in args for args in calls))
        endpoint.release('two', '192.0.2.1')
        self.assertIn(['/sbin/route', '-n', 'add', '-host', '192.0.2.1', '192.168.0.1'], calls)
        self.assertIn(['/sbin/route', '-n', 'delete', '-host', '192.0.2.1'], calls)

    def test_direct_endpoint_does_not_delete_preexisting_direct_route(self):
        calls = []

        def runner(args, **kwargs):
            calls.append(args)
            return SimpleNamespace(returncode=0, stdout='destination: 192.0.2.1\ngateway: 192.168.0.1\ninterface: en0\nflags: <UP,HOST,GATEWAY,STATIC>\n')

        endpoint = EndpointRoutes(lambda *args: None, runner)
        endpoint.ensure('one', '192.0.2.1')
        endpoint.release('one', '192.0.2.1')
        self.assertFalse(any('delete' in args or 'change' in args or 'add' in args for args in calls))


class SessionCleanupTests(unittest.TestCase):
    def test_route_scans_are_cached_but_sa_health_is_always_queried(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = StrongSwanEngine(configurations(), Path(directory), lambda *args: None)
            raw = ['state=ESTABLISHED local-vips=[ 10.20.0.1 ] '
                   'state=INSTALLED remote-ts=[ 10.30.0.0/24 ]']
            engine.swan = lambda *args, **kwargs: (0, raw[0])
            with patch.object(engine.routes, 'check', return_value={'route_error': None}) as check:
                for _ in range(10):
                    self.assertTrue(engine.status('one')['installed'])
                self.assertEqual(check.call_count, 1)
                # VIP changes trigger an immediate route scan.
                raw[0] = raw[0].replace('10.20.0.1', '10.20.0.2')
                engine.status('one')
                self.assertEqual(check.call_count, 2)
                # Expiration triggers a scan even if the SA is unchanged.
                with patch('vpn_backend.time.monotonic', return_value=time.monotonic() + 31):
                    engine.status('one')
                self.assertEqual(check.call_count, 3)
                # A dropped tunnel invalidates the cache before reconnection.
                connected = raw[0]
                raw[0] = ''
                self.assertFalse(engine.status('one')['installed'])
                raw[0] = connected
                engine.status('one')
                self.assertEqual(check.call_count, 4)

    def test_route_errors_and_peer_overlap_changes_are_not_hidden_by_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = StrongSwanEngine(configurations(), Path(directory), lambda *args: None)
            engine.swan = lambda *args, **kwargs: (0, 'state=ESTABLISHED local-vips=[ 10.20.0.1 ] '
                                                 'state=INSTALLED remote-ts=[ 10.30.0.0/24 ]')
            with patch.object(engine.routes, 'check', return_value={'route_error': 'Synthetic route error'}) as check:
                engine.status('one'); engine.status('one')
                self.assertEqual(check.call_count, 2)
            with patch.object(engine.routes, 'check', return_value={'route_error': None}) as check:
                engine.status('one'); engine.status('two'); engine.status('one')
                self.assertEqual(check.call_count, 3)

    def test_half_connected_ike_is_forced_out_before_new_handshake(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = StrongSwanEngine(configurations(), Path(directory), lambda *args: None)
            calls = []
            stale = [True]

            def swan(*args, **kwargs):
                calls.append(args)
                if '--force' in args:
                    self.assertNotIn('--timeout', args)
                    stale[0] = False
                if '--list-sas' in args and stale[0]:
                    return 0, 'list-sa { macvpn-one { state=ESTABLISHED child-sas { } } }'
                return 0, 'success=yes'

            engine.swan = swan
            engine.initiate('one', 45)
            force = next(i for i, args in enumerate(calls) if '--force' in args)
            start = next(i for i, args in enumerate(calls) if '--initiate' in args)
            self.assertLess(force, start)
            self.assertTrue(all('macvpn-two' not in args for args in calls))

    def test_cleanup_failure_prevents_new_handshake(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = StrongSwanEngine(configurations(), Path(directory), lambda *args: None)
            calls = []

            def swan(*args, **kwargs):
                calls.append(args)
                return 0, 'state=CONNECTING'

            engine.swan = swan
            with patch('vpn_backend.time.sleep'):
                with self.assertRaises(RuntimeError):
                    engine.initiate('one', 45)
            self.assertFalse(any('--initiate' in args for args in calls))

    def test_static_parent_is_preserved_when_route_get_shows_a_clone(self):
        calls = []
        def runner(args, **kwargs):
            calls.append(args)
            if args[0] == '/usr/sbin/netstat':
                output = '192.0.2.1 192.168.0.1 UGHS en0\n192.0.2.1 link#28 UHWIi utun8\n'
            else:
                output = 'gateway: 192.168.0.1\ninterface: en0\nflags: <UP,HOST,GATEWAY>\n'
            return SimpleNamespace(returncode=0, stdout=output)
        endpoint = EndpointRoutes(lambda *args: None, runner)
        endpoint.ensure('one', '192.0.2.1')
        endpoint.release('one', '192.0.2.1')
        self.assertFalse(any('add' in args or 'change' in args or 'delete' in args for args in calls))


class ConfigTests(unittest.TestCase):
    def test_privileged_children_do_not_inherit_injection_environment(self):
        with patch.dict(os.environ, {'PYTHONPATH': '/untrusted', 'PYTHONHOME': '/untrusted',
                                     'OPENSSL_CONF': '/untrusted', 'DYLD_INSERT_LIBRARIES': '/untrusted',
                                     'STRONGSWAN_CONF': '/untrusted', 'SUDO_UID': str(os.getuid())}):
            env = safe_environment(STRONGSWAN_CONF='/trusted/runtime.conf')
        self.assertEqual(env['STRONGSWAN_CONF'], '/trusted/runtime.conf')
        self.assertEqual(env['SUDO_UID'], str(os.getuid()))
        for name in ('PYTHONPATH', 'PYTHONHOME', 'OPENSSL_CONF', 'DYLD_INSERT_LIBRARIES'):
            self.assertNotIn(name, env)

    def test_atomic_status_file_is_not_world_readable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'status.json'
            path.write_text('{}'); path.chmod(0o644)
            atomic_json(path, {'ok': True})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(json.loads(path.read_text()), {'ok': True})

    def test_raw_status_requires_ike_and_child_and_extracts_routes(self):
        value = parse_sa('list-sa { vpn { state=ESTABLISHED local-vips=[ 10.20.0.1 ] '
                         'child-sas { child { state=INSTALLED remote-ts=[ 10.30.0.0/24 10.31.0.0/24 ] } } } }')
        self.assertTrue(value['installed'])
        self.assertEqual(value['virtual_ips'], ['10.20.0.1'])
        self.assertEqual(value['remote_subnets'], ['10.30.0.0/24', '10.31.0.0/24'])
        self.assertFalse(parse_sa('state=ESTABLISHED')['installed'])

    def test_profile_connection_and_secret_names_do_not_collide(self):
        for name, cfg in configurations().items():
            text = connection_config(cfg, cfg['shared_secret'])
            ike, child = connection_names(name)
            self.assertIn(ike + ' {', text)
            self.assertIn(child + ' {', text)
            self.assertIn('ike-' + name + ' {', text)
            self.assertIn('xauth-' + name + ' {', text)

    def test_configuration_reload_uses_revision_and_preserves_only_retained_profiles(self):
        import app_bridge
        for existing_revision, hardening in (('previous', 1), ('current', 1), ('current', 0)):
            with self.subTest(existing_revision=existing_revision, hardening=hardening), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                config_path = root / 'profiles.json'
                config_path.write_text(json.dumps({'revision': 'current', 'profiles': {
                    'one': dict(label='One', server='192.0.2.1', group='test', username='test-user',
                                password='test-password', shared_secret='test-psk')}}))
                calls = []
                def fake_rpc(runtime, request, **kwargs):
                    calls.append(request)
                    return dict(state=dict(version=4, direct_gateway_support=2, reconnect_support=2, hardening_support=hardening,
                                           config_path=str(config_path.resolve()), config_revision=existing_revision,
                                           profiles={'one': {'desired': True, 'auto_reconnect': False},
                                                     'deleted': {'desired': True}}))
                with patch('sys.argv', ['app_bridge.py', 'bootstrap', str(config_path)]), \
                     patch('app_bridge.os.geteuid', return_value=0), \
                     patch('app_bridge.os.environ', {}), \
                     patch('app_bridge.runtime_path', return_value=root), \
                     patch('app_bridge.rpc', side_effect=fake_rpc), \
                     patch('app_bridge.wait_backend_stopped'), \
                     patch('app_bridge.ensure_backend', return_value=root), \
                     contextlib.redirect_stdout(io.StringIO()) as output:
                    app_bridge.main()
                if existing_revision == 'previous' or hardening == 0:
                    self.assertIn(dict(action='shutdown'), calls)
                    self.assertIn(dict(action='connect', profile='one', auto_reconnect=False), calls)
                else:
                    self.assertFalse(any(call['action'] != 'status' for call in calls))
                self.assertFalse(any(call.get('profile') == 'deleted' for call in calls))
                self.assertNotIn('test-password', output.getvalue())

    def test_empty_managed_configuration_is_valid_but_cannot_connect(self):
        from strongvpn import read_config, settings
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'profiles.json'
            path.write_text('{"profiles": {}}')
            self.assertEqual(read_config(path)['profiles'], {})
            with self.assertRaisesRegex(ValueError, 'add one'):
                settings(path)


if __name__ == '__main__':
    unittest.main()
