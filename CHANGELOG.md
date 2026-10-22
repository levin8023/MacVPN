# Changelog

## 0.2.4

- Keep polling tunnel health while waiting to retry a timed-out handshake, so late completion is detected promptly.
- Retain monotonic backoff for control-interface failures and avoid starting duplicate handshakes during retry waits.
- Distinguish active reconnection from retry countdowns and display safe protocol-stage failure hints.
- Reload older backends when applying the reconnect fix; keep credential storage and administrator bootstrap unchanged.

## 0.2.3

- Restrict runtime status, logs, and the control socket to the controlling user; keep VICI root-only.
- Authenticate local requests before creating threads and cap concurrent control handlers.
- Honor exponential backoff on control failures using monotonic deadlines.
- Cache successful route checks for 30 seconds while polling SA health every 3 seconds.
- Avoid unchanged status writes, redundant preference writes, and idle Python status subprocesses.
- Sanitize child-process environments and disable Python environment/user-site overrides.
- Build fresh bundles and validate every release file against an explicit allowlist.
- Document strongSwan 6.1.0+ as the security baseline and verify two concurrent connections with 6.1.0.
- Retain plaintext local credential storage and the existing administrator bootstrap in this preview.

## 0.2.2

- Restore the menu panel to its pre-edit position after Save, Cancel, or the window close button.
- Keep manually positioned panels in place and clamp safely when a display is removed.
- Avoid reopening the panel during application exit.

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
