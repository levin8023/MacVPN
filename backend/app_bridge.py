"""Small GUI bridge: whitelisted local RPC and explicit administrator bootstrap."""
import json
import os
from pathlib import Path
import sys

from strongvpn import read_config, resolve_profile, settings
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
        print(json.dumps(rpc(runtime_path(), request), ensure_ascii=False))
        return
    if sys.argv[1] != 'bootstrap' or os.geteuid() != 0:
        raise ValueError('Administrator authorization is required to enable the backend')
    config_path = Path(sys.argv[2]).resolve()
    config = read_config(config_path)
    for name in config['profiles']:
        settings(config_path, name)
    restore = []
    try:
        existing = rpc(runtime_path(), dict(action='status'), timeout=2)['state']
    except (OSError, ValueError, RuntimeError):
        existing = None
    if existing and (existing.get('version', 0) < 4 or existing.get('direct_gateway_support', 0) < 2 or existing.get('reconnect_support', 0) < 1):
        for name, row in existing['profiles'].items():
            if row.get('desired'):
                try:
                    restore.append(resolve_profile(config['profiles'], name))
                except ValueError:
                    pass
        rpc(runtime_path(), dict(action='shutdown'))
        wait_backend_stopped(runtime_path())
    runtime = ensure_backend(config_path, 45)
    for name in restore:
        rpc(runtime, dict(action='connect', profile=name))
    print(json.dumps(rpc(runtime, dict(action='status')), ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
