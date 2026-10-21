#!/usr/bin/env python3
"""Check release contents without displaying any local credential values."""
import base64
import json
from pathlib import Path
import plistlib
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def verify(archive):
    private = [str(Path.home()).encode().lower()]
    local_files = [ROOT / 'config.local.json', Path.home() / 'Library/Application Support/MacVPN/profiles.json']
    for local in local_files:
        if not local.exists():
            continue
        config = json.loads(local.read_text())
        for name, item in config.get('profiles', {}).items():
            values = [name, item.get('label', ''), item.get('server', ''),
                      item.get('username', ''), item.get('password', ''), item.get('shared_secret', '')]
            for value in values:
                if isinstance(value, str) and len(value) >= 4:
                    private.append(value.encode().lower())
            for field in ('password', 'shared_secret'):
                value = item.get(field)
                if value:
                    private.append(('0s' + base64.b64encode(value.encode()).decode()).encode().lower())
    failures = []
    allowed = {'MacVPN.app', 'README.md', 'LICENSE', 'CHANGELOG.md'}
    with zipfile.ZipFile(archive) as bundle:
        for item in bundle.infolist():
            path = Path(item.filename)
            if (not path.parts or path.parts[0] != 'MacVPN' or '..' in path.parts or
                (len(path.parts) > 1 and path.parts[1] not in allowed)):
                failures.append(item.filename)
                continue
            if item.is_dir():
                continue
            if ('__pycache__' in path.parts or path.name.endswith(('.log', '.pyc')) or
                path.name in ('config.local.json', 'profiles.json')):
                failures.append(item.filename)
            data = bundle.read(item)
            if any(value in data.lower() for value in private):
                failures.append(item.filename)
            if path.name == 'Info.plist' and 'MacVPNConfigPath' in plistlib.loads(data):
                failures.append(item.filename)
    if failures:
        raise SystemExit('Release verification failed in: ' + ', '.join(sorted(set(failures))))
    print('PASS: release contains only allowed files; no local credentials or developer home path found.')


if __name__ == '__main__':
    verify(Path(sys.argv[1]))
