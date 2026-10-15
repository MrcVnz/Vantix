# Disclaimer

Last updated: October 15, 2026

## System-level access

Vantix runs with administrator privileges. Its tools can modify Windows settings, registry values, services, startup entries, power and network configuration, process behavior and system components. Cleanup tools can delete files and caches.

Changes can cause instability, connection loss, reduced security, increased power consumption, software conflicts or loss of functionality. A change that helps one computer can make another perform worse. Vantix does not guarantee higher FPS, lower latency, lower memory use or any other performance result.

## Recovery has limits

Vantix includes Windows restore-point support and records supported changes for undo. These mechanisms depend on Windows, the saved recovery data and the state of your computer. They cannot guarantee recovery from every failure or restore every deleted file.

Disk cleanup, emptied recycle-bin contents and other destructive operations may be permanent. Duplicate detection does not establish that a file is unnecessary: separate applications or folders may need their own copies.

Before using these tools:

- Back up important files independently of Vantix.
- Check that an appropriate recovery method is available.
- Read the description and risk information for each action.
- Review file selections before deletion.
- Apply changes in small groups and check their effect before continuing.

Keep change-history and recovery files until you have undone any changes you want to reverse. Removing the application or its local data does not automatically restore all Windows settings.

## Compatibility and testing

Vantix targets Windows on x64 hardware. Feature availability and results depend on the Windows build, drivers, permissions, hardware and installed software. A successful build does not establish compatibility with every configuration.

Use a disposable test environment for development that changes system state. Virtual machines are useful for recovery testing, but cannot reproduce every physical device, driver or performance characteristic. Network load tests consume real bandwidth and can temporarily affect other users of the connection.

## Warranty and liability

Vantix is provided as is. The warranty exclusions and limitations of liability in sections 15 and 16 of the [GNU GPL version 3](LICENSE) apply to the extent permitted by applicable law. No statement here removes rights or liabilities that cannot legally be excluded.

You are responsible for deciding whether a change is appropriate for a computer you are authorized to manage. For managed or critical systems, obtain the system administrator's approval before applying changes.

## Third parties

Vantix is an independent project and is not affiliated with or endorsed by Microsoft or the providers used by its network tools. Product names and trademarks belong to their respective owners.

See the [Terms of Use](TERMS.md) and [Privacy Policy](PRIVACY.md) for licensing context and data handling.
