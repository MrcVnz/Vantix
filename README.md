<div align="center">

<img src="./res/vantix.png" alt="Vantix icon" width="128" />

# Vantix

**A free, open-source Windows utility for system tuning, monitoring and maintenance.**

[![License](https://img.shields.io/badge/License-GPL--3.0--only-blue?style=flat-square)](./LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows_x64-0078d4?style=flat-square)](#requirements)
[![Built with](https://img.shields.io/badge/Built_with-Rust_%2B_Slint-dea584?style=flat-square)](#build-from-source)
[![Stars](https://img.shields.io/github/stars/MrcVnz/Vantix?style=flat-square)](https://github.com/MrcVnz/Vantix/stargazers)

[Getting started](#getting-started) · [Features](#features) · [Safety and recovery](#safety-and-recovery) · [Build from source](#build-from-source) · [Report a bug](https://github.com/MrcVnz/Vantix/issues)

Interface languages: **English** and **Português (Brasil)**.

</div>

## What Vantix does

Vantix brings Windows performance settings, live resource monitoring, memory tools, storage cleanup and network diagnostics into one desktop app. Inspect the current state, read the trade-offs and choose the changes that fit your machine.

It is not a one-click FPS fix. Results depend on your hardware, drivers, workload and existing settings. Some changes trade power efficiency or Windows features for different behavior. Measure the result and undo changes that do not help.

## Getting started

1. Get `vantix.exe` from [GitHub Releases](https://github.com/MrcVnz/Vantix/releases/latest), or [build it from source](#build-from-source).
2. Run the executable and approve the Windows administrator prompt. No installer is required.
3. Read the first-run notice, then check **Home** for a system overview and **Protection** for restore-point options.
4. Apply individual changes after reading their descriptions. Restart Windows when the app indicates it is needed.
5. Use **Protection** to review recorded changes and undo supported tweaks.

> [!WARNING]
> Back up important files before changing system settings or cleaning storage. A restore point is not a backup of your personal files, and cleanup cannot be reversed through Vantix's tweak history.

### Requirements

- Windows on an x64 PC. The repository currently targets `x86_64-pc-windows-gnullvm`; it does not provide a native ARM64 build.
- Administrator privileges to run the application.
- An internet connection for release checks, downloads and network tests. Local maintenance tools do not require an account.

Available settings and hardware readings depend on the Windows build, driver and device. Vantix is not a .NET application and does not require a separate .NET runtime.

## Features

| Area | What you can do |
| --- | --- |
| **Home** | View a system summary, check for updates and read release notes. |
| **Memory** | Inspect RAM usage, standby cache and commit usage. Run Quick, Standard or Deep cleanup, review cleanup history, or configure automatic cleanup by interval or RAM usage. |
| **Performance** | Adjust power and CPU settings. Optionally enable ProBalance to reduce interference from CPU-heavy background programs. |
| **Games** | Review gaming-related Windows settings and enable real-time game mode, with configurable game detection and background adjustments. |
| **Input** | Inspect mouse and keyboard devices, measure mouse input and adjust supported input and power-management settings. |
| **Background** | Manage startup entries and Windows services, with descriptions for known services and recorded startup-type changes. |
| **Internet** | Compare DNS resolvers, watch latency, inspect traffic, run connectivity and bufferbloat tests, and adjust supported network settings. |
| **Monitor** | Watch CPU, GPU, disk and network activity and inspect resource usage by process. |
| **Storage** | Analyze cleanup categories, select what to remove and inspect drive health information where the hardware exposes it. |
| **Disk space** | Find large files and explore which folders occupy storage. |
| **Duplicates** | Scan selected folders for duplicate files and review copies before removing them. |
| **Protection** | Manage Windows restore points, review recorded system changes and use Undo or Undo all for supported changes. |

### Live features and persistent changes

ProBalance, real-time game mode and automatic memory cleanup run while Vantix is open, including in the system tray when configured. Automatic memory cleanup, ProBalance and game mode are off by default.

Real-time game mode can adjust game priority, reduce background activity and pause Wi-Fi scanning. Its temporary adjustments have restoration and crash-recovery handling. Driver restrictions and anti-cheat software can prevent individual adjustments.

Registry, power-plan, network and service startup settings can remain changed after Vantix exits. Closing or deleting the executable does not undo them. Use the relevant Undo controls before removing the app or its recovery data.

## Safety and recovery

- **Review before applying.** Read each setting's effect and trade-offs. Avoid changing several tools' settings at once if they manage the same Windows features.
- **Restore points.** Vantix integrates with Windows System Protection and attempts to create a baseline restore point before its first system change when protection is enabled. Creation can fail; check the result before continuing.
- **Local undo records.** Supported tweaks save recovery information before system writes. Service startup changes are kept in the change history too.
- **Interrupted operations.** Incomplete changes can appear as **Recovery needed**. Review them instead of assuming an interrupted operation left Windows unchanged.
- **Deletion has different limits.** Cache cleanup, emptied recycle bins and other destructive actions are not restored by Undo all. Review selected files and categories first.
- **Updates are verified.** The updater checks the downloaded executable against the release's SHA-256 file and prepares it before replacing the current executable. A checksum is not a code-signing certificate or a guarantee that software is safe.

Recovery depends on the saved records and on Windows accepting the restoration. Keep a separate backup for anything you cannot afford to lose.

## Privacy and local data

Vantix has no account system, advertising or application analytics. It does not automatically upload logs, crash reports, files or a hardware inventory to the maintainer.

It is **not entirely offline**. It automatically checks GitHub for releases, normally once per day after a successful check. Downloads happen when requested. Network tools contact the relevant DNS providers, test hosts and services, including Cloudflare and Microsoft endpoints. Those providers receive the requests and your source IP address. There is currently no setting to disable automatic update checks.

Preferences, logs, cleanup history and recovery records normally live in:

```text
%APPDATA%\Vantix
```

Do not delete this folder before undoing changes you want to restore. Removing it does not reset Windows and can remove the information needed for recovery.

See the [Privacy Policy](./PRIVACY.md) for local files, network destinations and data-handling details.

## FAQ

### Will Vantix increase FPS or lower ping?

There is no guaranteed improvement. Use monitoring and diagnostics to identify a specific problem, change one relevant setting and compare under the same conditions. Network settings cannot remove the latency caused by distance or fix an overloaded remote server.

### Should I keep RAM usage as low as possible?

No. Windows uses available memory for caching. A lower number after cleanup is not, by itself, evidence of better performance. Deeper cleanup can cause temporary hitches or force applications to reload data.

### Can I undo everything?

No. Supported system tweaks and service startup changes have undo records, but file deletion and one-shot maintenance actions are different. Restore points also have limits and do not replace file backups.

### Why does Vantix need administrator access?

Its tools interact with system settings, services, storage and Windows APIs that require elevation. The executable's manifest requests administrator privileges at launch.

### What if Windows blocks the executable?

Do not assume a warning is harmless or disable security software to run it. Confirm that the download came from this repository, review the warning and verify the published checksum if available. You can also inspect and build the source yourself. A matching checksum confirms consistency with the published artifact, not trustworthiness.

### Does Vantix need to stay open?

Only for its live monitoring and background features. Persistent Windows settings remain changed after exit. Use **Exit** from the tray when you want to stop the application, rather than assuming that closing its window always exits it.

## Troubleshooting

| Problem | What to check |
| --- | --- |
| A change has no visible effect | Check whether a restart is required and whether the setting applies to your active power plan, adapter or hardware. Compare before and after under the same workload. |
| A restore point cannot be created | Check System Protection in **Protection**. Read the error and make a backup before deciding whether to proceed without a restore point. |
| A change shows **Recovery needed** | Review the affected setting and its Undo option. Keep the local recovery files and report repeated failures. |
| A cleanup skips files | Files can be locked, protected or outside safe cleanup paths. Close the application using them and analyze again; do not force-delete unknown files. |
| Drive health is unavailable | Some drives, controllers and USB enclosures do not expose the required data. Missing readings do not establish that a drive is healthy. |
| Update checks fail or find no release | Check connectivity and the [releases page](https://github.com/MrcVnz/Vantix/releases). The updater only offers stable releases with the expected assets. |

For a bug report, include the Vantix version, Windows build, relevant hardware, reproduction steps and any error shown. Review logs and screenshots for personal paths, addresses or credentials before posting them to [GitHub Issues](https://github.com/MrcVnz/Vantix/issues).

## Build from source

Build on Windows x64 with Git, Rust through rustup and an LLVM-MinGW toolchain on `PATH`. The repository selects `stable-x86_64-pc-windows-gnullvm` through `rust-toolchain.toml`. MSVC Build Tools alone do not supply the linker and resource tools used by this configuration.

```powershell
git clone https://github.com/MrcVnz/Vantix.git
cd Vantix
rustup show
cargo build --release --locked
```

The executable is written to `target\release\vantix.exe`. Compilation does not require an elevated shell; running Vantix does.

For development checks:

```powershell
cargo check --locked
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

Some tests depend on live Windows processes or devices. Integration tests marked `#[ignore]` may modify real system settings. Review and run them individually on a suitable test machine, not as an unrestricted batch on your everyday PC.

### Technical overview

- **Language:** Rust, edition 2024.
- **Interface:** Slint with a software renderer, embedded resources and bundled translations.
- **Platform integration:** Windows APIs, with Windows command-line tools for selected operations.
- **State:** Local JSON preferences and recovery journals, plus local logs.
- **Updates:** GitHub releases, executable and checksum assets, with backup and recovery handling.
- **Distribution:** A standalone executable, with static CRT configuration for the selected toolchain.

## Contributing

Bug reports, focused fixes, documentation improvements and translations are welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md) for setup, project structure, validation and contribution guidelines.

For security issues, use GitHub's private vulnerability reporting option if available. Otherwise, ask the maintainer for a private channel without posting exploit details or secrets in a public issue.

## Disclaimer and license

Vantix is provided **as is**, without warranty. System changes can affect stability, security, power consumption and application compatibility. Read the [Terms](./TERMS.md), [Privacy Policy](./PRIVACY.md) and [Disclaimer](./DISCLAIMER.md) before use.

Licensed under **GPL-3.0-only**. See [LICENSE](./LICENSE) and [THIRD-PARTY-NOTICES](./THIRD-PARTY-NOTICES) for the project license and bundled third-party notices.

<div align="center">

[Source](https://github.com/MrcVnz/Vantix) · [Releases](https://github.com/MrcVnz/Vantix/releases) · [Issues](https://github.com/MrcVnz/Vantix/issues) · [Back to top](#vantix)

</div>
