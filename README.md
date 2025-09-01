# Janus: Advanced Android Implant Framework

> **Disclaimer**: Janus is a research framework designed for authorized security testing and defensive analysis only. It demonstrates advanced persistence and stealth techniques for educational purposes. Use only in controlled, isolated environments with explicit permission.

## Overview

Janus is a sophisticated Android implant framework designed to demonstrate advanced persistence, stealth, and system manipulation capabilities. Named after the two-faced Roman god of transitions, Janus operates at both the kernel and userspace levels, providing unprecedented control over Android devices while maintaining complete invisibility.

## Key Features

### Persistence & Stealth (The Art of Being Invisible)

- **Module Hiding**: Unlinks kernel modules from the `struct modules` list
- **Process Hiding**: Manipulates the task list (`init_task`) to unlink specific processes
- **File Hiding**: Hooks `getdents64` and `readdir` syscalls to filter file/directory names
- **Network Hiding**: Hooks `seq_operations` for `/proc/net/tcp` and `/proc/net/udp` to hide connections
- **Log Wiping**: Directly modifies kernel ring buffer (`printk` log) and `logd` memory
- **Syscall Table Obfuscation**: Restores `sys_call_table` CR0 write protection after hooking
- **Kernel Symbol Hiding**: Removes functions from `/proc/kallsyms`
- **Interrupt Descriptor Table (IDT) Hooking**: For ultra-stealth system call hooking
- **Debugger Detection & Neutralization**: Identifies and cripples analysis tools (gdb, strace, ltrace)
- **ARM Memory Tagging (MTE) Emulation**: Fakes MTE checks to bypass hardware-based exploit mitigations
- **Fake `procfs`/`sysfs` Entries**: Creates misleading forensic data in `/proc` and `/sys`
- **Boot Image Patching**: Modifies `kernel.elf` on disk in the `boot` partition for permanent persistence
- **Firmware Re-flashing**: Writes payload to `persist` partition or modem firmware for hardware-level persistence

### Espionage & Data Harvesting (The All-Seeing Eye)

- **System-Wide Keylogger**: Hooks the `input_handler` chain to capture all touch/keystrokes
- **Clipboard Monitoring**: Intercepts `clipboard` service communications
- **SMS/MMS Interception**: Hooks the RIL (Radio Interface Layer) daemon
- **Notification Listener**: Parses `NotificationManagerService` memory
- **Microphone Activation**: Directly controls audio drivers to enable mic streaming
- **Camera Activation**: Controls camera subsystem without LED indication (on vulnerable hardware)
- **GPS Spoofing/Reading**: Manipulates GPS drivers for location deception/extraction
- **Bluetooth/NFC Sniffing**: Captures BT HCI traffic and NFC transactions
- **App Memory Scraping**: Reads process memory to extract decrypted messages and keys
- **Filesystem Change Monitoring**: Uses `inotify` hooks or monitors filesystem journals
- **Database Query Interception**: Hooks SQLite operations to exfiltrate queries and results

### System Manipulation & Control (The Master of Reality)

- **Arbitrary Code Execution**: Executes binaries/libraries in any process context
- **SELinux Disabling**: Patches enforcement variables in memory
- **DM-Verity Bypass**: Modifies kernel to bypass integrity checks
- **Read-Only Bypass**: Remounts partitions as read-write
- **Package Management Subversion**: Hooks `pm` installation commands
- **Network Proxy Injection**: Forces traffic through attacker-controlled proxies
- **DNS Poisoning**: Globally overrides DNS resolutions
- **SSL/TLS Bypass**: Hooks libssl libraries to disable certificate validation
- **VPN Bypass**: Routes traffic outside VPN tunnels via routing table manipulation
- **Battery Level Spoofing**: Reports false battery levels
- **Safe Mode Bypass**: Prevents booting into safe mode

### Network Warfare & C2 (The Command Node)

- **Raw Socket Creation**: Bypasses userland restrictions for custom packet crafting
- **Wi-Fi SSID Manipulation**: Controls `wpa_supplicant` to connect to malicious APs
- **ICMP/DNS Tunneling**: Creates covert C2 channels within the kernel
- **Kernel-based Packet Filtering**: Implements custom firewall invisible to userland tools
- **TCP Session Hijacking**: Resets or takes over existing TCP connections
- **Kernel-based Port Forwarding**: Redirects traffic between ports/IPs
- **C2 Traffic Masquerading**: Disguises C2 traffic as legitimate cloud service traffic
- **Network Stack Fingerprinting**: Actively fingerprints network environment from kernel space

### Hardware & Low-Level Exploitation (The Physicist)

- **CPU Frequency Manipulation**: Overclocks/underclocks CPU for performance attacks
- **GPU Control**: Launches compute attacks or uses GPU memory for payload storage
- **Voltage Manipulation**: Undervolts components to cause hardware damage (with kernel support)
- **Thermal Sensor Spoofing**: Triggers emergency shutdowns with false temperature reports
- **Peripheral Bricking**: Flashes corrupted firmware to Bluetooth/Wi-Fi chips
- **eSIM Profile Manipulation**: Controls eSIM manager to switch carriers or disable service
- **DMA Attacks**: Uses compromised peripheral DMA engines to attack other components
- **Secure World (TEE) Attack**: Attempts to pivot into TrustZone via shared memory/APIs

### Advanced Anti-Forensics & Deception (The Illusionist)

- **Forensic Tool Spoofing**: Returns benign data to known forensic tools
- **Timestomping**: Modifies file timestamps at the filesystem driver level
- **Full Device Encryption Bypass**: Extracts encryption keys from RAM or patches decryption
- **Secure Boot Bypass**: Patches kernel to skip signature checks
- **Fake System Updates**: Presets fake "System Update" UI to trick users
- **Factory Reset Protection Bypass**: Disables FRP to allow device reuse after theft
- **Simulate "Off" State**: Places radios in low-power state while maintaining listening capability

## Architecture

Janus employs a multi-layered architecture that operates across various privilege levels:

```
+-------------------------------------------------------+
|                 Userland Components                   |
|  (App disguising, high-level data collection)         |
+-------------------------------------------------------+
|                 Binder Interface                      |
+-------------------------------------------------------+
|                 Kernel Modules                        |
|  (Rootkit functionality, system manipulation)         |
+-------------------------------------------------------+
|                 Hardware Abstraction                  |
|  (Direct hardware access, firmware manipulation)      |
+-------------------------------------------------------+
```

## Defense Considerations

Janus demonstrates techniques that bypass conventional security measures:

- **Kernel Integrity Verification**: Implement kernel module signing enforcement
- **Runtime Integrity Monitoring**: Deploy solutions that detect kernel hooking
- **Hardware-assisted Security**: Utilize technologies like ARM MTE and PAC
- **Behavioral Analysis**: Monitor for anomalous system behaviors rather than specific signatures
- **Secure Boot Chain**: Strengthen bootloader protections to prevent persistent modifications

## Research Applications

Janus serves as:
- A red team tool for advanced penetration testing
- A defensive research platform for developing detection mechanisms
- An educational resource for understanding advanced rootkit techniques
- A testbed for evaluating Android security enhancements

## Legal and Ethical Notice

Janus is provided for research and educational purposes only. Unauthorized use against systems without explicit permission is illegal. Users assume all responsibility for ensuring compliance with applicable laws and regulations.

## License

This project is licensed for non-commercial research use only. Commercial use, modification, or redistribution is prohibited without explicit authorization.

---
**Warning**: The techniques demonstrated by Janus are extremely powerful and can cause permanent device damage if misused. Always exercise extreme caution in controlled environments.