# Sumon VPN — server list

This repository hosts the server list and WireGuard config files for the Sumon VPN Android app.

- `list.txt` — the server list the app reads. One server per line: `Name|https://.../file.conf`
- `*.conf` — WireGuard config files, one per server.

To add or remove a server: edit `list.txt` (and add/remove the matching `.conf` file). The app picks up changes when the user taps "update list" — no new app build needed.
