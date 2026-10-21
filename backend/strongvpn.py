#!/usr/bin/python3
"""Multi-VPN controller; credentials never enter process arguments."""
import argparse
import base64
import json
import os
import pwd
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parent
SWANCTL = Path('/opt/homebrew/bin/swanctl')
CHARON = Path('/opt/homebrew/opt/strongswan/libexec/ipsec/charon')
def connection_names(profile):
    return 'macvpn-' + profile, 'macvpn-' + profile + '-net'


def read_config(config_path):
    try:
        config = json.loads(Path(config_path).read_text())
    except json.JSONDecodeError:
        raise ValueError('Local VPN configuration is not valid JSON') from None
    if not isinstance(config, dict) or not isinstance(config.get('profiles'), dict):
        raise ValueError('Local VPN configuration must contain a profiles object')
    if not all(isinstance(key, str) and isinstance(item, dict)
                                         for key, item in config['profiles'].items()):
        raise ValueError('Each local profile must be an object with a name')
    return config


def resolve_profile(profiles, name):
    if name in profiles:
        return name
    matches = [key for key, item in profiles.items()
               if name == item.get('service') or name in item.get('aliases', [])]
    if len(matches) != 1:
        raise ValueError('Profile/service must identify exactly one local profile')
    return matches[0]


def settings(config_path, profile=None, service=None):
    config = read_config(config_path)
    profiles = config['profiles']
    if not profiles:
        raise ValueError('No VPN profiles configured; add one in the MacVPN app')
    if profile:
        profile = resolve_profile(profiles, profile)
    if service:
        selected = resolve_profile(profiles, service)
        if profile and selected != profile:
            raise ValueError('--profile and --service select different lines')
        profile = selected
    profile = profile or config.get('default_profile', next(iter(profiles)))
    if profile not in profiles:
        raise ValueError('Unknown local profile; use ./strongvpn profiles')
    if not re.fullmatch(r'[A-Za-z0-9_-]+', profile):
        raise ValueError('Profile names may contain letters, digits, underscores and hyphens only')
    item = profiles[profile]
    if not isinstance(item.get('direct_gateway', False), bool):
        raise ValueError('direct_gateway must be true or false')
    for field in ('label', 'server', 'group', 'username', 'password', 'shared_secret'):
        if not isinstance(item.get(field), str) or not item[field]:
            raise ValueError(f'Profile {profile} is missing a nonempty {field} in the saved configuration')
    return dict(profile=profile, label=item['label'], server=item['server'], group=item['group'],
                user=item['username'], password=item['password'], shared_secret=item['shared_secret'].encode(),
                direct_gateway=item.get('direct_gateway', False))


def quoted(value):
    if any(ord(c) < 32 for c in value):
        raise ValueError('Control characters are not supported in configuration identities')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def encoded(value):
    if isinstance(value, str):
        value = value.encode()
    return '0s' + base64.b64encode(value).decode('ascii')


def connection_config(cfg, psk):
    # Existing native-client logs show fallback to IKEv1 Aggressive Mode / DH2.
    # Match that existing gateway, without changing its configuration.
    group_id = '@#' + cfg['group'].encode().hex()
    profile_name, child_name = connection_names(cfg['profile'])
    return f'''connections {{
  {profile_name} {{
    version = 1
    aggressive = yes
    remote_addrs = {quoted(cfg['server'])}
    proposals = aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024
    encap = yes
    vips = 0.0.0.0
    pull = yes
    keyingtries = 1
    dpd_delay = 30s
    dpd_timeout = 120s
    local {{
      auth = psk
      id = {quoted(group_id)}
    }}
    local-xauth {{
      auth = xauth
      xauth_id = {quoted(cfg['user'])}
    }}
    remote {{
      auth = psk
      id = %any
    }}
    children {{
      {child_name} {{
        local_ts = dynamic
        remote_ts = 0.0.0.0/0
        esp_proposals = aes256-sha1,aes128-sha1,3des-sha1
        rekey_time = 50m
        dpd_action = clear
        start_action = none
      }}
    }}
  }}
}}
secrets {{
  ike-{cfg['profile']} {{
    id = {quoted(group_id)}
    secret = {encoded(psk)}
  }}
  xauth-{cfg['profile']} {{
    id = {quoted(cfg['user'])}
    secret = {encoded(cfg['password'])}
  }}
}}
'''


def daemon_config(runtime):
    return f'''charon {{
  # Use ephemeral local UDP ports; do not stop Apple's VPN daemon.
  port = 0
  port_nat_t = 0
  cisco_unity = yes
  install_routes = yes
  load = nonce openssl kdf kernel-pfkey kernel-pfroute socket-default vici xauth-generic unity osx-attr
  filelog {{
    stdout {{
      default = 1
      flush_line = yes
      ike_name = yes
    }}
  }}
  syslog {{
    daemon {{ default = -1 }}
    auth {{ default = -1 }}
  }}
  plugins {{
    vici {{ socket = unix://{runtime}/charon.vici }}
    openssl {{ load_legacy = yes }}
    kernel-pfkey {{ route_via_internal = yes }}
  }}
}}
'''


def write_private(path, contents):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        stream.write(contents)


PHASE_LABELS = {
    'disconnected': '未连接', 'connecting': '连接中', 'connected': '已连接',
    'reconnecting': '等待重连', 'auth_failed': '认证失败（重试已暂停）',
    'failed': '失败', 'disconnecting': '断开中',
}


def cached_status():
    from vpn_backend import runtime_path
    for path in (runtime_path() / 'status.json', ROOT / '.build/strongvpn-status.json'):
        try:
            value = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        value['stale'] = time.time() - value.get('timestamp', 0) > 20
        return value
    return None


def print_status(config, state, selected=None, as_json=False):
    if as_json:
        print(json.dumps(state or dict(engine_ready=False, stale=True, profiles={}), ensure_ascii=False))
        return
    if not state:
        print('多连接后台尚未启动。若旧版命令仍在运行，先在其终端按 Ctrl+C 完成一次升级切换。')
    stale = bool(state and state.get('stale'))
    if stale:
        print('后台状态已过期，以下连接状态无法确认。')
    for name, item in config['profiles'].items():
        if selected and name != selected:
            continue
        row = (state or {}).get('profiles', {}).get(name, {})
        phase = '状态未知' if stale or not row else PHASE_LABELS.get(row.get('phase'), '状态未知')
        ips = ','.join(row.get('virtual_ips', []))
        print(f"{name:12} {item['label']:16} {phase}" + (f'  IP={ips}' if ips else ''))
        if row.get('error'):
            print('  ' + row['error'])
        if row.get('route_error'):
            print('  路由异常：' + row['route_error'])
    for conflict in (state or {}).get('route_overlaps', []):
        print('网段重叠：' + ' / '.join(conflict['profiles']) + ' — ' + ' / '.join(conflict['subnets']))


def wait_disconnected(runtime, profile, timeout):
    from vpn_backend import rpc
    deadline = time.monotonic() + timeout + 10
    while time.monotonic() < deadline:
        state = rpc(runtime, {'action': 'status'})['state']
        row = state['profiles'][profile]
        if row['desired']:
            raise RuntimeError('Another command requested this VPN again; disconnect was superseded')
        if row['phase'] == 'disconnected':
            return state
        time.sleep(0.2)
    raise RuntimeError('Disconnect is still pending; use status to check progress')


def main():
    from vpn_backend import ensure_backend, rpc, runtime_path, serve, wait_backend_stopped
    parser = argparse.ArgumentParser(description='Multi-VPN controller with a shared background strongSwan engine.')
    parser.add_argument('command', choices=['profiles', 'check', 'status', 'connect', 'disconnect',
                                           'run', 'test', 'shutdown', '_serve'])
    parser.add_argument('--config', default=str(Path(pwd.getpwuid(int(os.environ.get('SUDO_UID', os.getuid()))).pw_dir) / 'Library/Application Support/MacVPN/profiles.json'))
    parser.add_argument('--profile', help='Profile name or a configured alias')
    parser.add_argument('--service', help='Compatibility alias for an existing service name')
    parser.add_argument('--timeout', type=int, default=45)
    parser.add_argument('--json', action='store_true', help='Machine-readable status for a future menu-bar app')
    args = parser.parse_args()
    if not 10 <= args.timeout <= 300:
        raise ValueError('Timeout must be between 10 and 300 seconds')
    config = read_config(args.config)
    if args.command == 'profiles':
        for name, item in config['profiles'].items():
            print(f"{name}: {item['label']} — {item['server']}")
        return 0
    if args.command == 'status':
        selected = settings(args.config, args.profile, args.service)['profile'] if args.profile or args.service else None
        print_status(config, cached_status(), selected, args.json)
        return 0
    for executable in (SWANCTL, CHARON):
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ValueError('Missing executable: ' + str(executable))
    if args.command == 'shutdown':
        if os.geteuid() != 0:
            raise RuntimeError('Use ./strongvpn so sudo can authorize tunnel management')
        rpc(runtime_path(), dict(action='shutdown'))
        wait_backend_stopped(runtime_path())
        print('VPN backend stopped.')
        return 0
    cfg = settings(args.config, args.profile, args.service)
    if args.command == 'check':
        connection_config(cfg, cfg['shared_secret'])
        print(f"OK: {cfg['profile']} ({cfg['label']}) — {cfg['server']}; JSON authentication fields complete.")
        print('Independent IKE/CHILD names: ' + ', '.join(connection_names(cfg['profile'])))
        return 0
    if os.geteuid() != 0:
        raise RuntimeError('Use ./strongvpn so sudo can authorize tunnel management')
    if args.command == '_serve':
        configs = {name: settings(args.config, name) for name in config['profiles']}
        serve(os.environ.get('MACVPN_CONFIG_ORIGIN', str(Path(args.config).resolve())), configs, args.timeout, config_revision=config.get('revision'))
        return 0
    if args.command in ('disconnect', 'shutdown'):
        if args.command == 'disconnect' and not (args.profile or args.service):
            raise ValueError('Specify --profile for disconnect; shutdown explicitly disconnects all VPNs')
        response = rpc(runtime_path(), dict(action=args.command, profile=cfg['profile']))
        state = response['state']
        if args.command == 'disconnect':
            print('正在断开所选 VPN，其他连接继续运行。', flush=True)
            state = wait_disconnected(runtime_path(), cfg['profile'], args.timeout)
        else:
            print('正在关闭共享后台并断开全部 VPN。', flush=True)
            wait_backend_stopped(runtime_path())
            state = cached_status()
        print_status(config, state, cfg['profile'] if args.command == 'disconnect' else None)
        if args.command == 'shutdown':
            print('共享后台已关闭。')
        return 0
    runtime = ensure_backend(args.config, args.timeout)
    running_profiles = rpc(runtime, {'action': 'status'})['state']['profiles']
    if cfg['profile'] not in running_profiles:
        raise RuntimeError('Profile names changed; run ./strongvpn shutdown, then reconnect to reload the JSON')
    before = running_profiles[cfg['profile']]
    already_requested = before['desired']
    rpc(runtime, dict(action='connect', profile=cfg['profile'], timeout=args.timeout))
    print(f"{cfg['profile']}: 后台正在管理连接。其他 VPN 可同时连接。", flush=True)
    deadline = time.monotonic() + args.timeout + 10
    last_phase = None
    try:
        while True:
            state = rpc(runtime, {'action': 'status'})['state']
            row = state['profiles'][cfg['profile']]
            phase = row['phase']
            if phase != last_phase:
                print_status(config, state, cfg['profile'])
                sys.stdout.flush()
                last_phase = phase
            if phase == 'connected':
                if args.command == 'test':
                    print('PASS: selected VPN is connected; other profiles are unchanged.')
                    return 0
                if args.command == 'connect':
                    print('连接由后台保持，关闭此终端也会继续运行。')
                    return 0
            if phase == 'auth_failed' or (phase == 'disconnected' and not row['desired']):
                return 1
            if args.command != 'run' and time.monotonic() >= deadline:
                if args.command == 'test':
                    print('测试等待超时；本次测试新增的连接将被断开。')
                else:
                    print('等待超时；后台会继续重试。使用 status 查看，或 disconnect --profile 停止。')
                return 1
            time.sleep(1)
    except KeyboardInterrupt:
        if args.command == 'run':
            rpc(runtime, dict(action='disconnect', profile=cfg['profile']))
            print('\n正在断开本条 VPN。', flush=True)
            wait_disconnected(runtime, cfg['profile'], args.timeout)
            print('\n已断开本条 VPN，其他连接继续运行。')
        return 130
    finally:
        if args.command == 'test' and not already_requested:
            rpc(runtime, dict(action='disconnect', profile=cfg['profile']))
            wait_disconnected(runtime, cfg['profile'], args.timeout)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        sys.exit(1)
