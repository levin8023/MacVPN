"""One charon process, independently controlled/reconnected VPN profiles."""
import fcntl
import ctypes
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import socketserver
import subprocess
import tempfile
import threading
import time

from strongvpn import ROOT, CHARON, SWANCTL, connection_config, connection_names, daemon_config, write_private, encoded


def atomic_json(path, value):
    fd, name = tempfile.mkstemp(prefix=path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, ensure_ascii=False)
        os.chmod(name, 0o644)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def runtime_path():
    return Path('/private/var/run') / ('macvpn-' + str(int(os.environ.get('SUDO_UID', os.getuid()))))


def peer_uid(connection):
    uid, gid = ctypes.c_uint(), ctypes.c_uint()
    if ctypes.CDLL(None, use_errno=True).getpeereid(connection.fileno(), ctypes.byref(uid), ctypes.byref(gid)):
        raise PermissionError('Cannot identify local client')
    return uid.value


def prepare_runtime(runtime):
    if runtime.exists() and (runtime.is_symlink() or runtime.stat().st_uid != os.geteuid()):
        raise RuntimeError('Unsafe runtime directory')
    runtime.mkdir(mode=0o700, exist_ok=True)
    os.chmod(runtime, 0o700)


def wait_backend_stopped(runtime, timeout=25):
    try:
        descriptor = os.open(runtime / 'backend.lock', os.O_RDWR | os.O_NOFOLLOW)
    except FileNotFoundError:
        return
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeError('VPN backend has not stopped; check its log before restarting')
                time.sleep(0.1)
    finally:
        os.close(descriptor)


def rpc(runtime, request, timeout=20):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(timeout)
        client.connect(str(runtime / 'control.sock'))
        client.sendall(json.dumps(request).encode() + b'\n')
        data = bytearray()
        while b'\n' not in data:
            chunk = client.recv(8192)
            if not chunk:
                raise RuntimeError('VPN backend closed its response')
            data.extend(chunk)
            if len(data) > 262144:
                raise RuntimeError('VPN backend response is too large')
        response = json.loads(bytes(data).split(b'\n', 1)[0])
        if not response.get('ok'):
            raise RuntimeError(response.get('error', 'VPN backend request failed'))
        return response


class Redactor:
    def __init__(self, configs):
        self.values = set()
        for cfg in configs.values():
            for value in (cfg['user'], cfg['password'], cfg['shared_secret']):
                if isinstance(value, bytes):
                    try:
                        value = value.decode()
                    except UnicodeDecodeError:
                        continue
                if value:
                    self.values.add(value)
                    self.values.add(encoded(value))
        self.values = sorted(self.values, key=len, reverse=True)

    def __call__(self, message):
        for value in self.values:
            message = message.replace(value, '[REDACTED]')
        return message


def parse_sa(output):
    """Extract only noncredential fields from swanctl's raw VICI dump."""
    installed = 'state=ESTABLISHED' in output and 'state=INSTALLED' in output
    nets = []
    for block in re.findall(r'remote-ts=\[([^\]]*)\]', output):
        for token in block.split():
            try:
                value = ipaddress.ip_network(token, strict=False)
                nets.append(str(value))
            except ValueError:
                pass
    vips = []
    for block in re.findall(r'local-vips=\[([^\]]*)\]', output):
        for token in block.split():
            try:
                vips.append(str(ipaddress.ip_address(token)))
            except ValueError:
                pass
    return dict(installed=installed, remote_subnets=sorted(set(nets)), virtual_ips=sorted(set(vips)))


class RouteGuard:
    """Repair only exact routes owned by a configured gateway, never defaults."""
    def __init__(self, logger, runner=None):
        self.log = logger
        self.runner = runner or subprocess.run
        self.lock = threading.Lock()
        self.active = {}

    def run(self, arguments):
        return self.runner(arguments, capture_output=True, text=True, timeout=5)

    @staticmethod
    def table(output):
        routes = {}
        for line in output.splitlines():
            fields = line.split()
            if len(fields) < 4:
                continue
            address, _, bits = fields[0].partition('/')
            parts = address.split('.')
            if not 1 <= len(parts) <= 4 or not all(p.isdigit() for p in parts):
                continue
            try:
                subnet = ipaddress.ip_network('.'.join(parts + ['0'] * (4 - len(parts))) + '/' + (bits or str(len(parts) * 8)), strict=False)
            except ValueError:
                continue
            routes[(str(subnet), fields[3])] = fields[1]
        return routes

    def check(self, profile, sa, server):
        with self.lock:
            self.active[profile] = sa if sa['installed'] else None
            if not sa['installed']:
                return {}
            interfaces = self.run(['/sbin/ifconfig'])
            if interfaces.returncode:
                return dict(route_error='Cannot inspect VPN interfaces')
            current, candidates = None, set()
            for line in interfaces.stdout.splitlines():
                header = re.match(r'^(\w+):', line)
                if header:
                    current = header.group(1)
                address = re.match(r'\s+inet (\S+) ', line)
                if address and address.group(1) in sa['virtual_ips'] and current and re.fullmatch(r'utun\d+', current):
                    candidates.add(current)
            if len(candidates) != 1:
                return dict(route_error='VPN virtual IP does not identify a unique tunnel interface')
            interface = candidates.pop()
            table = self.run(['/usr/sbin/netstat', '-rn', '-f', 'inet'])
            owned_routes = self.table(table.stdout) if not table.returncode else {}
            errors, repaired = [], []
            for value in sa['remote_subnets']:
                subnet = ipaddress.ip_network(value)
                if subnet.version != 4 or subnet.prefixlen == 0:
                    errors.append('Automatic route repair is limited to IPv4 split networks')
                    continue
                conflict = any(other and name != profile and any(
                    subnet.version == ipaddress.ip_network(net).version and subnet.overlaps(ipaddress.ip_network(net))
                    for net in other['remote_subnets']) for name, other in self.active.items())
                if conflict:
                    errors.append('Overlapping VPN networks require manual route selection: ' + value)
                    continue
                lookup = self.run(['/sbin/route', '-n', 'get', '-net', value])
                fields = dict(re.findall(r'^\s*([\w]+):\s*(\S+)', lookup.stdout, re.M))
                try:
                    destination = fields['destination']
                    exact = ipaddress.ip_network(destination + '/' + fields.get('mask', '32'), strict=False) == subnet
                except (KeyError, ValueError):
                    exact = False
                if lookup.returncode == 0 and exact and fields.get('interface') == interface:
                    continue
                # No route is added or replaced unless it is the exact negotiated
                # network and still points at this profile's configured gateway.
                gateway = fields.get('gateway') or owned_routes.get((value, fields.get('interface')))
                if not exact or gateway != server:
                    errors.append('Route is missing or owned elsewhere: ' + value)
                    continue
                result = self.run(['/sbin/route', '-n', 'change', '-net', value, '-interface', interface])
                verify = self.run(['/sbin/route', '-n', 'get', '-net', value])
                actual = re.search(r'^\s*interface:\s*(\S+)', verify.stdout, re.M)
                if result.returncode or verify.returncode or not actual or actual.group(1) != interface:
                    errors.append('Route repair failed: ' + value)
                    continue
                repaired.append(value)
                self.log(profile, 'Corrected route ' + value + ' to ' + interface)
            return dict(route_error='; '.join(errors) or None, tunnel_interface=interface,
                        route_checked_at=time.time(), routes_repaired=repaired)


class EndpointRoutes:
    """Optional physical exit for a VPN peer; unrelated proxy routes are untouched."""
    def __init__(self, logger, runner=None):
        self.log, self.runner = logger, runner or subprocess.run
        self.pins, self.owners = {}, {}
        self.lock = threading.Lock()

    def run(self, args):
        return self.runner(args, capture_output=True, text=True, timeout=5)

    def lookup(self, destination):
        response = self.run(['/sbin/route', '-n', 'get', destination])
        if response.returncode:
            raise RuntimeError('Cannot inspect VPN gateway route')
        return dict(re.findall(r'^\s*([\w]+):\s*(\S+)', response.stdout, re.M))

    def gateway(self, server, current):
        table = self.run(['/usr/sbin/netstat', '-rn', '-f', 'inet'])
        return current.get('gateway') or RouteGuard.table(table.stdout).get((server + '/32', current.get('interface')))

    def has_static_route(self, server, interface, gateway):
        table = self.run(['/usr/sbin/netstat', '-rn', '-f', 'inet'])
        return any(len(parts) >= 4 and parts[0] == server and parts[1] == gateway and
                   'S' in parts[2] and parts[3] == interface
                   for parts in (line.split() for line in table.stdout.splitlines()))

    def ensure(self, profile, server):
        ip = ipaddress.ip_address(server)
        if ip.version != 4:
            raise ValueError('direct_gateway requires a literal IPv4 VPN server address')
        with self.lock:
            default = self.lookup('default')
            interface, gateway = default.get('interface', ''), default.get('gateway', '')
            if not re.fullmatch(r'en\d+', interface):
                raise RuntimeError('Cannot identify a physical default interface for direct_gateway')
            ipaddress.IPv4Address(gateway)
            current = self.lookup(server)
            self.owners.setdefault(server, set()).add(profile)
            physical = current.get('interface') == interface and self.gateway(server, current) == gateway
            if physical and ('STATIC' in current.get('flags', '') or self.has_static_route(server, interface, gateway)):
                return
            if not physical and not current.get('interface', '').startswith('utun') and server not in self.pins:
                raise RuntimeError('VPN gateway uses another route; automatic override refused')
            # Prefer a new unscoped static /32. Changing a proxy's scoped cloned
            # route alone is temporary and can be replaced on the next lookup.
            response = self.run(['/sbin/route', '-n', 'add', '-host', server, gateway])
            if response.returncode:
                response = self.run(['/sbin/route', '-n', 'change', '-host', server, gateway, '-static'])
            if response.returncode:
                raise RuntimeError('Cannot install the direct VPN gateway route')
            self.pins[server] = (interface, gateway)
            if self.lookup(server).get('interface') != interface:
                raise RuntimeError('Direct VPN gateway route did not select the physical interface')
            self.log(profile, 'VPN gateway ' + server + ' uses physical exit ' + interface)

    def release(self, profile, server):
        with self.lock:
            self.owners.setdefault(server, set()).discard(profile)
            if self.owners[server] or server not in self.pins:
                return
            interface, gateway = self.pins.pop(server)
            current = self.lookup(server)
            if current.get('interface') == interface and self.gateway(server, current) == gateway:
                self.run(['/sbin/route', '-n', 'delete', '-host', server])


class StrongSwanEngine:
    def __init__(self, configs, runtime, logger):
        self.configs, self.runtime, self.log = configs, runtime, logger
        self.process = None
        self.vici = runtime / 'backend-charon.vici'
        self.conf = runtime / 'backend-strongswan.conf'
        self.secret_file = runtime / 'backend-swanctl.conf'
        self.env = dict(os.environ, STRONGSWAN_CONF=str(self.conf))
        self.routes = RouteGuard(logger)
        self.endpoints = EndpointRoutes(logger)

    def healthy(self):
        return self.process is not None and self.process.poll() is None and self.vici.exists()

    def swan(self, *arguments, timeout=15):
        result = subprocess.run([str(SWANCTL), *arguments, '--uri', 'unix://' + str(self.vici)],
                                env=self.env, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout + result.stderr

    def start(self):
        if self.healthy():
            return
        for path in (self.conf, self.secret_file, self.vici):
            path.unlink(missing_ok=True)
        # Keep certificates optional without emitting missing-directory warnings.
        for name in ('x509', 'x509ca', 'x509ocsp', 'x509aa', 'x509ac', 'x509crl',
                     'pubkey', 'private', 'rsa', 'ecdsa', 'pkcs8', 'pkcs12'):
            (self.runtime / name).mkdir(mode=0o700, exist_ok=True)
        conf = daemon_config(self.runtime).replace('unix://' + str(self.runtime / 'charon.vici'),
                                                    'unix://' + str(self.vici))
        write_private(self.conf, conf)
        combined = '\n'.join(connection_config(cfg, cfg['shared_secret']) for cfg in self.configs.values())
        write_private(self.secret_file, combined)
        try:
            self.process = subprocess.Popen([str(CHARON)], env=self.env, stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT, text=True, start_new_session=True)
            threading.Thread(target=self._logs, args=(self.process,), daemon=True).start()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise RuntimeError('charon exited during startup; see the backend log')
                if self.vici.exists():
                    os.chmod(self.vici, 0o600)
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError('charon did not create its control socket')
            code, output = self.swan('--load-all', '--noprompt', '--file', str(self.secret_file))
            self.log(None, output.rstrip())
            if code:
                raise RuntimeError('Unable to load the shared VPN configuration')
        except Exception:
            self.stop()
            raise
        finally:
            self.secret_file.unlink(missing_ok=True)

    def _logs(self, process):
        for line in process.stdout:
            profile = None
            for name in self.configs:
                ike, _ = connection_names(name)
                if re.search(r'(?<![\w-])' + re.escape(ike) + r'(?![\w-])', line):
                    profile = name
                    break
            self.log(profile, line.rstrip())

    def status(self, profile):
        ike, _ = connection_names(profile)
        code, output = self.swan('--list-sas', '--ike', ike, '--raw')
        if code:
            raise RuntimeError('Unable to query the VPN tunnel')
        sa = parse_sa(output)
        try:
            if sa['installed'] and self.configs[profile].get('direct_gateway'):
                self.endpoints.ensure(profile, self.configs[profile]['server'])
            sa.update(self.routes.check(profile, sa, self.configs[profile]['server']))
        except Exception:
            sa['route_error'] = 'Cannot verify VPN routes; check the backend log'
        return sa

    def clear_sessions(self, profile):
        """Remove every SA for this profile, including half-negotiated IKE SAs."""
        ike, _ = connection_names(profile)
        code, output = self.swan('--list-sas', '--ike', ike, '--raw')
        if code:
            raise RuntimeError('Cannot inspect previous VPN sessions')
        if not re.search(r'\bstate=', output):
            return
        self.swan('--terminate', '--ike', ike, '--timeout', '3', timeout=5)
        for _ in range(10):
            code, output = self.swan('--list-sas', '--ike', ike, '--raw')
            if code:
                raise RuntimeError('Cannot verify VPN session cleanup')
            if not re.search(r'\bstate=', output):
                with self.routes.lock:
                    self.routes.active.pop(profile, None)
                return
            # Force has no --timeout: the daemon must discard stale IKE state,
            # rather than waiting for an unreachable peer's DELETE response.
            self.swan('--terminate', '--ike', ike, '--force', timeout=5)
            time.sleep(0.1)
        raise RuntimeError('Previous VPN session did not stop; retry deferred')

    def initiate(self, profile, timeout):
        self.clear_sessions(profile)
        if self.configs[profile].get('direct_gateway'):
            self.endpoints.ensure(profile, self.configs[profile]['server'])
        ike, child = connection_names(profile)
        code, output = self.swan('--initiate', '--child', child, '--ike', ike,
                                 '--timeout', str(timeout), '--loglevel', '1', timeout=timeout + 5)
        self.log(profile, output.rstrip())
        auth_failed = bool(re.search(r'XAuth authentication.*failed|no shared key found|AUTHENTICATION_FAILED',
                                     output, re.I))
        return dict(auth_failed=auth_failed, success=code == 0)

    def terminate(self, profile):
        ike, _ = connection_names(profile)
        self.clear_sessions(profile)
        self.endpoints.release(profile, self.configs[profile]['server'])

    def stop(self):
        process = self.process
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        self.process = None
        for name, cfg in self.configs.items():
            try:
                self.endpoints.release(name, cfg['server'])
            except Exception:
                self.log(name, 'Unable to clean up a direct gateway route')
        with self.routes.lock:
            self.routes.active.clear()
        for path in (self.secret_file, self.conf, self.vici):
            path.unlink(missing_ok=True)


class Backend:
    def __init__(self, configs, runtime, status_path, config_path, timeout=45, engine=None,
                 poll_interval=3, retry_interval=15):
        self.configs, self.runtime = configs, runtime
        self.status_path, self.config_path = status_path, str(config_path)
        self.timeout, self.poll_interval, self.retry_interval = timeout, poll_interval, retry_interval
        self.condition = threading.Condition(threading.RLock())
        self.stop_event = threading.Event()
        self.stopped = False
        self.engine_ready = threading.Event()
        self.publish_lock = threading.Lock()
        self.log_lock = threading.Lock()
        self.redact = Redactor(configs)
        self.threads = []
        self.workers = {}
        self.storage_errors = {}
        self.log_max_bytes = 5 * 1024 * 1024
        self.states = {name: dict(profile=name, label=cfg['label'], server=cfg['server'],
                                  phase='disconnected', desired=False, generation=0, attempts=0,
                                  handshake_timeout=timeout, auto_reconnect=True,
                                  error=None, route_error=None, tunnel_interface=None,
                                  virtual_ips=[], remote_subnets=[], next_retry=0,
                                  updated_at=time.time()) for name, cfg in configs.items()}
        self.engine = engine or StrongSwanEngine(configs, runtime, self.log)

    def log(self, profile, message):
        message = self.redact(message)
        line = time.strftime('%Y-%m-%d %H:%M:%S') + ' ' + message + '\n'
        paths = [self.status_path.parent / 'strongvpn-backend.log']
        if profile:
            paths.append(self.status_path.parent / ('strongvpn-' + profile + '.log'))
        with self.log_lock:
            for path in paths:
                try:
                    # Keep two older files. Rotation and writes are best effort:
                    # diagnostic I/O must never kill a tunnel worker or log reader.
                    if path.exists() and path.stat().st_size >= self.log_max_bytes:
                        older = Path(str(path) + '.2')
                        previous = Path(str(path) + '.1')
                        if previous.exists():
                            os.replace(previous, older)
                        os.replace(path, previous)
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o644)
                    with os.fdopen(fd, 'w') as stream:
                        stream.write(line)
                    with self.condition:
                        self.storage_errors.pop(path.name, None)
                except OSError as error:
                    with self.condition:
                        self.storage_errors[path.name] = error.errno

    def snapshot(self):
        with self.condition:
            profiles = {}
            for name, state in self.states.items():
                profiles[name] = {key: value for key, value in state.items() if key != 'generation'}
            overlaps = []
            active = [name for name, state in profiles.items() if state['phase'] == 'connected']
            for index, left in enumerate(active):
                for right in active[index + 1:]:
                    for a in profiles[left]['remote_subnets']:
                        for b in profiles[right]['remote_subnets']:
                            if ipaddress.ip_network(a).overlaps(ipaddress.ip_network(b)):
                                overlaps.append(dict(profiles=[left, right], subnets=[a, b]))
            return dict(version=4, pid=os.getpid(), timestamp=time.time(), config_path=self.config_path,
                        direct_gateway_support=2, reconnect_support=2,
                        storage_error=('Status or log storage is unavailable; VPN control continues in memory'
                                       if self.storage_errors else None),
                        engine_ready=self.engine_ready.is_set(), profiles=profiles, route_overlaps=overlaps,
                        stopping=self.stop_event.is_set() and not self.stopped)

    def publish(self):
        with self.publish_lock:
            try:
                atomic_json(self.status_path, self.snapshot())
            except OSError as error:
                # Do not log here: the log filesystem may have the same failure.
                with self.condition:
                    self.storage_errors['status.json'] = error.errno
            else:
                with self.condition:
                    self.storage_errors.pop('status.json', None)

    def update(self, profile, generation=None, **changes):
        with self.condition:
            state = self.states[profile]
            if generation is not None and generation != state['generation']:
                return False
            state.update(changes, updated_at=time.time())
            self.condition.notify_all()
        self.publish()
        return True

    def set_reconnect(self, profile, enabled):
        if not isinstance(enabled, bool) or profile not in self.states:
            raise ValueError('Invalid reconnect preference')
        self.update(profile, auto_reconnect=enabled)

    def connect(self, profile, timeout=None, auto_reconnect=None):
        if timeout is not None and (not isinstance(timeout, int) or not 10 <= timeout <= 300):
            raise ValueError('Handshake timeout must be between 10 and 300 seconds')
        with self.condition:
            if profile not in self.states:
                raise ValueError('Unknown VPN profile')
            state = self.states[profile]
            if auto_reconnect is not None:
                if not isinstance(auto_reconnect, bool):
                    raise ValueError('Invalid reconnect preference')
                state['auto_reconnect'] = auto_reconnect
            if state['desired']:
                return
            state.update(desired=True, generation=state['generation'] + 1, phase='connecting',
                         error=None, attempts=0, next_retry=0,
                         handshake_timeout=timeout if timeout is not None else self.timeout)
            self.condition.notify_all()
        self.publish()

    def disconnect(self, profile):
        with self.condition:
            if profile not in self.states:
                raise ValueError('Unknown VPN profile')
            state = self.states[profile]
            state.update(desired=False, generation=state['generation'] + 1, phase='disconnecting')
            self.condition.notify_all()
        self.publish()

    def _worker(self, profile):
        delay = self.retry_interval
        while not self.stop_event.is_set():
            with self.condition:
                state = dict(self.states[profile])
                if not state['desired'] and state['phase'] != 'disconnecting':
                    self.condition.wait(timeout=self.poll_interval)
                    continue
            if not self.engine_ready.wait(timeout=self.poll_interval):
                continue
            generation = state['generation']
            try:
                # Only this worker performs operations for this profile. A disconnect
                # queues cleanup after an in-flight handshake, without touching peers.
                if not state['desired']:
                    self.engine.terminate(profile)
                    self.update(profile, generation, phase='disconnected', error=None,
                                route_error=None, tunnel_interface=None, virtual_ips=[], remote_subnets=[], next_retry=0)
                    continue
                sa = self.engine.status(profile)
                if sa['installed']:
                    self.update(profile, generation, phase='connected', error=None,
                                route_error=sa.get('route_error'), tunnel_interface=sa.get('tunnel_interface'),
                                virtual_ips=sa['virtual_ips'], remote_subnets=sa['remote_subnets'], next_retry=0)
                    delay = self.retry_interval
                elif state['attempts'] > 0 and not state['auto_reconnect']:
                    self.engine.terminate(profile)
                    self.update(profile, generation, phase='failed', desired=False,
                                virtual_ips=[], remote_subnets=[], next_retry=0,
                                error='Tunnel disconnected; automatic reconnect is off')
                elif time.time() >= state['next_retry']:
                    self.update(profile, generation, phase='connecting' if state['attempts'] == 0 else 'reconnecting',
                                attempts=state['attempts'] + 1)
                    # The second check prevents a queued disconnect from starting a new handshake.
                    with self.condition:
                        if self.states[profile]['generation'] != generation or not self.states[profile]['desired']:
                            continue
                    result = self.engine.initiate(profile, state['handshake_timeout'])
                    with self.condition:
                        stale = self.states[profile]['generation'] != generation or not self.states[profile]['desired']
                    if stale:
                        self.engine.terminate(profile)
                        continue
                    if result['auth_failed']:
                        self.engine.terminate(profile)
                        self.update(profile, generation, desired=False, phase='auth_failed',
                                    error='Authentication failed; retries paused', next_retry=0)
                    else:
                        sa = self.engine.status(profile)
                        if sa['installed']:
                            self.update(profile, generation, phase='connected', error=None,
                                        route_error=sa.get('route_error'), tunnel_interface=sa.get('tunnel_interface'),
                                        virtual_ips=sa['virtual_ips'], remote_subnets=sa['remote_subnets'], next_retry=0)
                            delay = self.retry_interval
                        else:
                            # Do not accumulate partially negotiated SAs on retries.
                            # initiate() clears stale IKE state before the next attempt.
                            # Retain the physical endpoint pin throughout retries.
                            with self.condition:
                                retry = self.states[profile]['auto_reconnect']
                            self.update(profile, generation, phase='reconnecting' if retry else 'failed', desired=retry,
                                        virtual_ips=[], remote_subnets=[], route_error=None, tunnel_interface=None,
                                        error='Tunnel not installed; waiting to retry' if retry else 'Connection failed; automatic reconnect is off',
                                        next_retry=time.time() + delay if retry else 0)
                            delay = min(delay * 2, 300)
                elif state['phase'] == 'connected':
                    self.update(profile, generation, phase='reconnecting', virtual_ips=[], remote_subnets=[])
            except Exception as error:
                self.log(profile, 'Control operation failed: ' + str(error))
                with self.condition:
                    current = dict(self.states[profile])
                retry = current['desired'] and current['auto_reconnect']
                if current['desired'] and not retry:
                    try:
                        self.engine.terminate(profile)
                    except Exception:
                        self.log(profile, 'Session cleanup pending after control failure')
                self.update(profile, generation,
                            phase=('reconnecting' if retry else 'failed') if current['desired'] else 'disconnecting',
                            desired=retry if current['desired'] else False,
                            virtual_ips=[], remote_subnets=[], route_error=None, tunnel_interface=None,
                            error='Control operation failed; waiting to retry' if retry else 'Control operation failed',
                            next_retry=time.time() + delay)
                delay = min(delay * 2, 300)
            self.stop_event.wait(self.poll_interval)

    def _worker_entry(self, profile):
        try:
            self._worker(profile)
        except Exception as error:
            self.log(profile, 'VPN worker exited unexpectedly: ' + type(error).__name__)

    def _start_worker(self, profile):
        thread = threading.Thread(target=self._worker_entry, args=(profile,),
                                  name='vpn-' + profile, daemon=True)
        self.workers[profile] = thread
        # Prune exited threads so repeated recoveries do not retain them forever.
        self.threads = [item for item in self.threads if item.is_alive()]
        self.threads.append(thread)
        thread.start()

    def _monitor(self):
        delay = self.retry_interval
        while not self.stop_event.wait(self.poll_interval):
            if not self.engine.healthy():
                self.engine_ready.clear()
                with self.condition:
                    active = [(name, state['generation']) for name, state in self.states.items() if state['desired']]
                for name, generation in active:
                    self.update(name, generation, phase='reconnecting', virtual_ips=[], remote_subnets=[],
                                error='VPN engine restarting')
                try:
                    self.engine.stop()
                    self.engine.start()
                    self.engine_ready.set()
                    delay = self.retry_interval
                except Exception as error:
                    self.log(None, 'Engine restart failed: ' + str(error))
                    self.stop_event.wait(delay)
                    delay = min(delay * 2, 300)
            for name, worker in list(self.workers.items()):
                if not worker.is_alive() and not self.stop_event.is_set():
                    with self.condition:
                        state = self.states[name]
                        if state['desired']:
                            state.update(phase='reconnecting', next_retry=0,
                                         error='VPN worker recovered; checking tunnel', updated_at=time.time())
                    self.log(name, 'Restarting an exited VPN worker')
                    self._start_worker(name)
            self.publish()

    def start(self):
        self.engine.start()
        self.engine_ready.set()
        for name in self.configs:
            self._start_worker(name)
        thread = threading.Thread(target=self._monitor, daemon=True)
        thread.start()
        self.threads.append(thread)
        self.publish()

    def stop(self):
        self.stop_event.set()
        with self.condition:
            for state in self.states.values():
                state.update(desired=False, generation=state['generation'] + 1)
            self.condition.notify_all()
        self.engine_ready.clear()
        self.engine.stop()
        for thread in self.threads:
            thread.join(timeout=2)
        self.stopped = True
        for name in self.states:
            self.update(name, phase='disconnected', virtual_ips=[], remote_subnets=[], next_retry=0)


class ControlServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, address, handler, allowed_uid=None):
        self.allowed_uid = os.getuid() if allowed_uid is None else allowed_uid
        super().__init__(address, handler)


class ControlHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(5)
        try:
            if peer_uid(self.connection) not in (0, self.server.allowed_uid):
                raise PermissionError('Unauthorized local client')
            line = self.rfile.readline(65537)
            if len(line) > 65536:
                raise ValueError('Request too large')
            request = json.loads(line)
            action = request.get('action')
            backend = self.server.backend
            if action == 'connect':
                if backend.stop_event.is_set():
                    raise ValueError('Backend is stopping')
                backend.connect(request.get('profile'), request.get('timeout'), request.get('auto_reconnect'))
            elif action == 'set-reconnect':
                backend.set_reconnect(request.get('profile'), request.get('enabled'))
            elif action == 'disconnect':
                backend.disconnect(request.get('profile'))
            elif action == 'shutdown':
                backend.stop_event.set()
            elif action != 'status':
                raise ValueError('Unsupported action')
            response = dict(ok=True, state=backend.snapshot())
        except Exception:
            response = dict(ok=False, error='Backend request failed; check the profile name and backend log')
        self.wfile.write(json.dumps(response).encode() + b'\n')


def serve(config_path, configs, timeout):
    runtime = runtime_path()
    prepare_runtime(runtime)
    lock_fd = os.open(runtime / 'backend.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise RuntimeError('VPN backend is already running')
    backend = Backend(configs, runtime, runtime / 'status.json', config_path, timeout)
    server = None
    signal.signal(signal.SIGTERM, lambda *_: backend.stop_event.set())
    signal.signal(signal.SIGINT, lambda *_: backend.stop_event.set())
    try:
        backend.start()
        control = runtime / 'control.sock'
        control.unlink(missing_ok=True)
        server = ControlServer(str(control), ControlHandler, allowed_uid=int(os.environ.get('SUDO_UID', os.getuid())))
        server.backend = backend
        server.timeout = 0.5
        # The directory is searchable but not listable. VICI and credential files
        # stay root-only. Every control request also checks the kernel peer UID.
        os.chmod(control, 0o666)
        os.chmod(runtime, 0o711)
        while not backend.stop_event.is_set():
            server.handle_request()
    except Exception as error:
        backend.log(None, 'Backend stopped: ' + str(error))
        raise
    finally:
        if server:
            server.server_close()
            (runtime / 'control.sock').unlink(missing_ok=True)
        backend.stop()
        os.close(lock_fd)


def ensure_backend(config_path, timeout):
    runtime = runtime_path()
    prepare_runtime(runtime)
    start_fd = os.open(runtime / 'startup.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(start_fd, fcntl.LOCK_EX)
        try:
            response = rpc(runtime, {'action': 'status'}, timeout=2)
        except (OSError, RuntimeError, ValueError):
            response = None
        if response:
            os.chmod(runtime, 0o711)
            if response['state']['config_path'] != os.environ.get('MACVPN_CONFIG_ORIGIN', str(Path(config_path).resolve())):
                raise RuntimeError('Backend uses another JSON; shut it down before changing configurations')
            return runtime
        # The socket closes before charon finishes cleanup. Wait for that old
        # manager to release ownership before starting a replacement.
        wait_backend_stopped(runtime)
        # Do not hijack/kill the previous foreground daemon, or clear its socket.
        legacy = os.open(runtime / 'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(legacy, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError('The old single-VPN process is still running. Press Ctrl+C in its terminal once, then retry the new command')
        finally:
            os.close(legacy)
        process = subprocess.Popen(['/usr/bin/python3', str(ROOT / 'strongvpn.py'), '_serve',
                                    '--config', str(Path(config_path).resolve()), '--timeout', str(timeout)],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError('VPN backend startup failed; see ' + str(runtime / 'strongvpn-backend.log'))
            try:
                rpc(runtime, {'action': 'status'}, timeout=1)
                return runtime
            except (OSError, RuntimeError, ValueError):
                time.sleep(0.2)
        raise RuntimeError('VPN backend startup timed out; check its log before retrying')
    finally:
        os.close(start_fd)
