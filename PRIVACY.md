# Privacy Policy

Last updated: October 15, 2026

## Scope

This policy describes the Vantix desktop application in this repository. Vantix has no user account, advertising system or application analytics service. It does not automatically upload logs, crash reports, file contents or a hardware inventory to the maintainer.

Vantix processes system information locally and makes network connections for updates and network tools. It is not an entirely offline application.

## Information processed on your computer

Depending on the features you use, Vantix reads hardware and operating-system information, running processes, resource usage, startup entries, services, registry settings, storage information and network configuration. Network tools can inspect connection addresses, per-process traffic statistics and nearby Wi-Fi network names and identifiers.

Storage tools inspect file names, paths and sizes. Duplicate detection reads file contents locally to compare them. These scans do not upload your files.

## Local storage

Vantix normally stores its data in `%APPDATA%\Vantix`. If `APPDATA` is unavailable, it falls back to a `Vantix` directory under the system temporary directory.

Stored data includes:

- Preferences, the accepted notice version and acceptance time, selected folders, custom ping hosts and game detection preferences in `settings.json`.
- Memory cleanup history in `history.json` and saved system changes used for undo in `changes.json`, with supporting recovery state.
- Game-mode recovery state in `game.json` and activity in `game-mode.log`.
- Operational errors in `vantix.log` and crash information in `crash.log`, including rotated logs where applicable.
- Update-related files, including downloaded update data and release notes in `whats-new.json`.

Logs, saved settings and exported reports can contain process names, paths, network details and other information about your computer. Cleanup history is limited to the latest 200 entries. Other records may remain until replaced, rotated, cleared or removed locally.

You control these local files. Before removing recovery data, undo the changes you want to reverse, disable automatic features and close Vantix. Deleting the data folder does not restore Windows settings and can remove information needed for undo.

## Network connections

| Feature | Destination and information exchanged |
| --- | --- |
| Update checks | The GitHub API at `api.github.com/repos/MrcVnz/Vantix/releases/latest`. The app checks automatically when due, normally at a 24-hour interval after a successful check, and supports manual checks. Failed automatic checks may be retried after an hour. |
| Update downloads | GitHub release asset URLs and their download infrastructure, when you choose to download an update. Vantix downloads the executable and its SHA-256 file. |
| Live latency | Your gateway, Cloudflare's public resolver and custom hosts you add. Host names may be resolved through your configured DNS service. |
| DNS tests and configuration | DNS requests to tested resolvers. Available providers include Cloudflare, Google, Quad9, OpenDNS and AdGuard. Changing the system resolver also affects DNS requests made by other applications. |
| Bufferbloat and speed measurement | Downloads and generated upload data sent to `speed.cloudflare.com`. These tests consume bandwidth; the upload payload is test data, not your files. |
| Connectivity diagnostics | DNS and connectivity probes, including Cloudflare endpoints and Microsoft's `www.msftconnecttest.com/connecttest.txt`. The Microsoft connectivity probe uses plain HTTP. |
| Project links | GitHub pages opened in your browser when you follow repository, contribution or issue links. |

Remote providers receive the source IP address and the requests needed to serve these connections. HTTP requests can also carry application identification headers. Their logging and retention are outside the maintainer's control. GitHub describes its processing in its [General Privacy Statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).

Local maintenance features do not require an account or an internet connection. Network tests and update retrieval require connectivity. The current settings do not include an automatic-update-check opt-out.

## Reports you choose to share

Opening a GitHub issue or pull request shares your GitHub identity and any text, screenshots or files you submit. Public reports can be viewed by anyone. Review attachments and remove credentials, personal paths, addresses and other sensitive details before posting. Vantix does not automatically submit these reports.

## Changes and questions

This policy will be updated when the application's data handling changes. For questions, open a [public issue](https://github.com/MrcVnz/Vantix/issues) with a description that does not disclose sensitive information.
