"""Small GUI bridge: whitelisted local RPC and explicit administrator bootstrap."""
import json
import os
from pathlib import Path
import sys

from strongvpn import read_config, settings
from vpn_backend import ensure_backend, rpc, runtime_path, wait_backend_stopped


def main():
    if sys.argv[1] == 'request':
        action = sys.argv[2]
        if action not in ('status', 'connect', 'disconnect', 'set-reconnect', 'shutdown'):
            raise ValueError('Unsupported action')
        request = dict(action=action)
        if len(sys.argv) > 3:
            request['profile'] = sys.argv[3]
        if len(sys.argv) > 4:
            if sys.argv[4] not in ('true', 'false'):
                raise ValueError('Invalid preference')
            request['auto_reconnect' if action == 'connect' else 'enabled'] = sys.argv[4] == 'true'
        print(json.dumps(rpc(runtime_path(), request, timeout=3 if action == 'status' else 20), ensure_ascii=False))
        return
    if sys.argv[1] != 'bootstrap' or os.geteuid() != 0:
        raise ValueError('Administrator authorization is required to enable the backend')
    config_path = Path(sys.argv[2]).resolve()
    config = read_config(config_path)
    for name in config['profiles']:
        settings(config_path, name)
    if not config['profiles']:
        raise ValueError('Add a VPN profile before enabling the backend')
    restore = []
    try:
        existing = rpc(runtime_path(), dict(action='status'), timeout=2)['state']
    except (OSError, ValueError, RuntimeError):
        existing = None
    origin = os.environ.get('MACVPN_CONFIG_ORIGIN', str(config_path))
    if existing and (existing.get('version', 0) < 4 or
                     existing.get('direct_gateway_support', 0) < 2 or
                     existing.get('reconnect_support', 0) < 2 or
                     existing.get('config_path') != origin or
                     existing.get('config_revision') != config.get('revision')):
        for name, row in existing['profiles'].items():
            if row.get('desired') and name in config['profiles']:
                restore.append((name, row.get('auto_reconnect', True)))
        rpc(runtime_path(), dict(action='shutdown'))
        wait_backend_stopped(runtime_path())
    runtime = ensure_backend(config_path, 45)
    for name, enabled in restore:
        rpc(runtime, dict(action='connect', profile=name, auto_reconnect=enabled))
    print(json.dumps(rpc(runtime, dict(action='status')), ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
