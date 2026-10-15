# Contributing to Vantix

Vantix is a Windows desktop application written in Rust with a Slint interface. Contributions can include bug fixes, reproducible reports, translations, documentation and improvements to system tools.

Discuss substantial features in an [issue](https://github.com/MrcVnz/Vantix/issues) before implementing them. Keep each pull request focused on one problem and avoid unrelated formatting or refactoring.

## Development setup

Use Windows x64 with Git, Rust installed through rustup, and an LLVM-MinGW toolchain available on `PATH`. The repository selects `stable-x86_64-pc-windows-gnullvm` in `rust-toolchain.toml`. This is a GNU LLVM Windows build, so installing only the MSVC C++ tools does not provide the selected toolchain's linker and resource tools.

Fork the repository, then clone your fork:

```powershell
git clone https://github.com/YOUR-USERNAME/Vantix.git
cd Vantix
git remote add upstream https://github.com/MrcVnz/Vantix.git
git switch -c fix/short-description
rustup show
cargo build --locked
```

The debug executable is `target\debug\vantix.exe`. Its manifest requests administrator access. Build commands do not require an elevated shell; running the application can change your computer. Use a test machine or disposable Windows VM for system-changing work.

## Project structure

| Path | Responsibility |
| --- | --- |
| `src/main.rs` | Application state, UI callbacks, background work and feature coordination. |
| `src/pages/` | Home and monitor page integration. |
| `src/tweaks.rs`, `src/boost.rs`, `src/reg.rs` | Tweak definitions, system changes and registry helpers. |
| `src/settings.rs`, `src/restore.rs` | Preferences, history, change journals and Windows restore points. |
| `src/governor.rs`, `src/memory.rs` | Process management, game mode and memory tools. |
| `src/net.rs`, `src/input.rs`, `src/monitor.rs`, `src/etw.rs` | Networking, input, monitoring and event tracing. |
| `src/disk.rs`, `src/dupes.rs`, `src/space.rs`, `src/health.rs` | Cleanup, duplicate detection, disk usage and health. |
| `src/services.rs`, `src/startup.rs`, `src/system.rs` | Windows services, startup integration and shared platform operations. |
| `src/update.rs` | GitHub release checks, downloads, hash validation and executable replacement. |
| `ui/` | Slint pages, reusable controls and visual definitions. |
| `lang/` | Translation catalogs. |
| `res/`, `build.rs` | Embedded resources, manifest and UI compilation. |

Follow an existing implementation in the relevant module before adding a new abstraction or dependency.

## System changes and recovery

For a new tweak, document the Windows behavior it changes, the supported configurations, the risks and how to verify the result. Use the existing tweak and journal flow where applicable.

- Detect the actual state before applying a change. Handle unsupported hardware and unavailable Windows APIs explicitly.
- Preserve the previous state needed for undo. Restoring a guessed default is not the same as restoring the user's setting.
- Handle partial failures and interrupted operations. Keep recovery information useful across restarts and crashes.
- Keep blocking Windows calls, scans and network work off the UI thread. Follow the existing background-job and UI-update patterns.
- Report failures accurately. Do not show success if an operation failed or only partly completed.
- Explain destructive actions and their limits. Do not imply that a restore point can recover every deleted file.
- Keep unsafe code narrow and document the Windows API assumptions that make it valid.

Test apply, repeated apply, undo, unsupported cases and failure behavior when relevant. For recovery changes, include restart or interrupted-operation checks. Do not claim performance gains without measurements and the conditions used to obtain them.

## Validation

From the repository root:

```powershell
cargo fmt --check
cargo check --locked
cargo test --locked
cargo build --release --locked
```

Run checks appropriate to the change and report exactly what you ran. Documentation-only changes normally need link and content checks, not a binary rebuild.

Tests are embedded in the Rust modules. Several Windows integration tests are marked `#[ignore]` because they use real devices, network connections or system settings. Review a test before running it. Run an individual ignored test only in an appropriate test environment:

```powershell
cargo test --locked TEST_NAME -- --ignored --nocapture --test-threads=1
```

Replace `TEST_NAME` with the specific test you reviewed. Do not run the entire ignored suite on your everyday computer. Some tests modify services, adapters, registry values or startup integration. A VM snapshot does not replace physical-hardware testing for hardware-specific changes.

For UI changes, include screenshots and check scaling, long text, English and Brazilian Portuguese. For system behavior, describe the Windows build, relevant hardware, initial state, result and undo result.

## Code and translations

Write code, comments, documentation and pull requests in English. Follow `rustfmt.toml` and the conventions of the surrounding code. Avoid em dashes in new project text.

The current application supports English and Brazilian Portuguese. Slint source strings use `@tr(...)`; the Portuguese catalog is `lang/pt_BR/LC_MESSAGES/vantix.po`, bundled by `build.rs`. Keep existing translations consistent when changing user-facing text. Additional languages need both a catalog and integration with the language selection in Rust and the UI.

Do not add telemetry, external requests or uploaded diagnostics without discussing the behavior and updating the privacy documentation. Never commit credentials, private reports, local settings or build output. New dependencies and bundled assets must have compatible licenses and appropriate notices in `THIRD-PARTY-NOTICES`.

## Pull requests

Target `main` and describe the problem, the resulting behavior and the validation performed. Link the related issue when there is one. Include known limitations and any tests you could not run.

Use concise commit subjects with `feat:`, `fix:`, `chore:` or `release:` as appropriate. Leave version changes, tags and release publication to the maintainer unless explicitly requested. Do not include unrelated generated files or changes to `Cargo.lock` without a dependency reason.

By submitting a contribution, you agree to provide it under the project's [GPL-3.0-only license](LICENSE). Only submit work you have the right to contribute and preserve required third-party attribution.

## Bug reports

Include the Vantix version, Windows version and build, relevant hardware, reproduction steps, expected behavior and actual behavior. Mention other tools that manage the same settings. Share only relevant log excerpts after removing private paths, addresses and credentials. Issues and attachments are public.

For a suspected vulnerability, avoid publishing exploit details or secrets in a public issue. Use GitHub's private vulnerability reporting option if the repository exposes it. Otherwise, ask the maintainer for a private reporting channel without disclosing the vulnerability itself.

## Release artifacts

Release publication is handled by the maintainer. The current updater reads the latest stable GitHub release and expects these assets:

- `vantix.exe`, built with `cargo build --release --locked` from `target\release\vantix.exe`.
- `vantix.exe.sha256`, containing the executable's SHA-256 in checksum-file format: `<64 hexadecimal characters>  vantix.exe`.

Use a version tag matching the package version, such as `vX.Y.Z`, and describe the changes in the release body. Drafts and prereleases are not offered by the current updater. Keep the license, third-party notices and corresponding source available with the distribution as required by their licenses. A matching checksum verifies consistency with the published hash; it is not a code-signing certificate.

See [TERMS.md](TERMS.md), [PRIVACY.md](PRIVACY.md) and [DISCLAIMER.md](DISCLAIMER.md) for the user-facing project documents.
