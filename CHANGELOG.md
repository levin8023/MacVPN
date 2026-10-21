# Changelog

## 0.2.1

- Remove empty-state explanatory copy and the implementation footer from the panel.
- Respect read-only storage directories and preserve existing profiles when saving fails.

## 0.2.0

- Create, edit, and delete VPN profiles directly in the app, with masked authentication fields.
- Start without preparing a configuration file; store profiles privately in Application Support.
- Apply saved changes by configuration revision and restore retained connection requests.
- Disconnect a profile before deleting it; keep other tunnels running until changes are applied.
- Start fresh without importing or reading older external configuration files.

## 0.1.1

- Keep tunnel control and reconnect workers running when status-cache or log writes fail.
- Recover an exited profile worker without restarting the shared engine or peer tunnels.
- Fall back to live local RPC when the status cache stops updating, and show storage errors.
- Rotate diagnostic logs with two bounded backups.
- Add regression coverage for full disks, error-handler write failures, and worker recovery.

## 0.1.0

- Initial public preview for Apple Silicon macOS.
- Menu bar controls, per-profile status, concurrent tunnels, and automatic reconnect.
- Clean up stale IKE sessions before retrying interrupted handshakes.
- Validate VPN routes and optionally keep individual VPN gateways on the physical network.
- Separate local credentials, source code, build output, and release archives.
