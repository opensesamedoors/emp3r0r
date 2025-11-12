# emp3r0r

<img width="200" height="200" alt="emp3r0r" src="https://github.com/user-attachments/assets/65550dfb-ea5a-49e8-a036-8c7df349f5f4" />


**A powerful Linux/Windows post-exploitation framework designed by Linux users, for Linux environments**

[![Discord](https://img.shields.io/badge/Discord-Join%20Server-7289da?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/vU98aQtk9f)
[![GitHub Sponsors](https://img.shields.io/badge/GitHub-Sponsor-ff69b4?style=for-the-badge&logo=github&logoColor=white)](https://github.com/sponsors/jm33-m0)
[![Screenshots](https://img.shields.io/badge/View-Screenshots-blue?style=for-the-badge)](./Screenshots.md)

---

## SSH Credential Harvesting in Action

<https://github.com/user-attachments/assets/e735b325-d9ad-43bd-b34d-79f395cc4b8f>

---

## What is emp3r0r?

emp3r0r is a comprehensive post-exploitation framework that stands out as one of the first C2 platforms purpose-built for Linux environments. While most frameworks treat Linux as an afterthought, emp3r0r puts it front and center, delivering robust capabilities for penetration testing and red team operations across both Linux and Windows targets.

### Why emp3r0r?

- **Linux-Native Architecture**: Built from the ground up for Linux targets with full Windows compatibility, not the other way around
- **Extensible Python Environment**: Deploy a complete Python3 runtime (15MB) with Impacket, Requests, and MySQL libraries via the `vaccine` module
- **Universal Module Support**: Execute Bash, PowerShell, Python, DLL, SO, and EXE modules seamlessly across platforms
- **Advanced Stealth Capabilities**: Dynamic process obfuscation, file concealment through Glibc hijacking, and anti-analysis techniques
- **Modern Infrastructure**: WireGuard + mTLS operator authentication, HTTP2/TLS with JA3 evasion, KCP-based UDP tunneling

---

## Quick Start

### Installation

```bash
curl -sSL https://raw.githubusercontent.com/jm33-m0/emp3r0r/refs/heads/v3/install.sh | bash
```

### 3-Step Deployment

#### 1️⃣ Initialize the Server

```bash
emp3r0r server --c2-hosts 'your.domain.com' --port 12345 --operators 2
```

This command deploys emp3r0r with:

- HTTP2/TLS agent listener on randomized port with valid TLS certificate for your domain
- WireGuard operator service on specified port (12345)
- Operator mTLS server on `wg_ip:12346`
- Pre-configured operator slots (2 in this example)

The server automatically generates:

1. **WireGuard Server Configuration** - server IP, port, and public key
2. **WireGuard Operator Configurations** - unique credentials for each operator
3. **Client Connection Commands** - ready-to-execute commands for immediate deployment

#### 2️⃣ Connect as Operator

Copy the generated connection command and replace `<C2_PUBLIC_IP>` with your server's IP:

```bash
emp3r0r client --c2-port 12345 --server-wg-key 'key...' --c2-host your.domain.com
```

**Connection Process:**

- Each operator receives a unique, pre-configured connection command
- For local testing: use `127.0.0.1` as the C2 host and run the generated command in the same tmux session
- For remote operations: replace `<C2_PUBLIC_IP>` with your server's public IP or domain
- System prompts for operator's private key (displayed in server configuration)
- WireGuard connectivity is automatically established and secured

#### 3️⃣ Generate Agent Payloads

Use the `generate` command from within the emp3r0r shell interface to create customized agent payloads for your targets.

---

## Core Capabilities

<details>
<summary><strong>Stealth & Evasion</strong></summary>

- **Advanced Process Hiding**
  - Dynamic `argv` manipulation to obfuscate process listings
  - File and PID concealment via Glibc hijacking techniques
  - Anti-debugging and anti-analysis countermeasures

- **Secure Command & Control**
  - HTTP2/TLS with UTLS implementation to defeat JA3 fingerprinting
  - KCP-based fast, multiplexed UDP tunneling for high-performance operations
  - Native TOR and CDN proxy support for anonymization
  - WireGuard + mTLS for operator authentication and secure channels

</details>

<details>
<summary><strong>Operator Experience</strong></summary>

- **Professional CLI Interface**
  - Built on console and cobra frameworks for robust command handling
  - Intelligent auto-completion with syntax highlighting
  - Native tmux integration for parallel operations
  - Bring Your Own Shell support (elvish compatibility)

- **Advanced Shell Integration**
  - SSH with full PTY support for native terminal experience
  - Windows compatibility with standard OpenSSH clients
  - SFTP integration for efficient remote file operations

</details>

<details>
<summary><strong>Network Pivoting</strong></summary>

- **Intelligent Network Traversal**
  - Automatic agent bridging through Shadowsocks proxy chains
  - Reverse proxy capabilities via SSH and KCP tunnels
  - External target access for otherwise unreachable endpoints
  - Bidirectional port mapping supporting both TCP and UDP protocols
  - Agent-side Socks5 proxy with full UDP support

</details>

<details>
<summary><strong>Payload Delivery</strong></summary>

- **Flexible Staging Options**
  - Multi-stage payload delivery for both Linux and Windows
  - HTTP listener with AES encryption and compression
  - DLL agent and shellcode agent for Windows environments
  - Shared library stager for Linux targets

- **In-Memory Execution**
  - Execute Bash, PowerShell, Python, and native ELF binaries without touching disk
  - CGO-based ELF loader for memory-only execution
  - Process injection and shellcode injection capabilities
  - ELF binary patching for sophisticated persistence mechanisms

</details>

<details>
<summary><strong>Post-Exploitation Arsenal</strong></summary>

- **Credential Harvesting**
  - OpenSSH credential harvesting with real-time monitoring
  - Cross-platform memory dumping capabilities
  - Windows mini-dump extraction (pypykatz compatible)

- **Additional Capabilities**
  - Bettercap integration for network attacks
  - Multiple persistence mechanisms across platforms
  - Privilege escalation tools with automated suggestions
  - Comprehensive system information collection
  - File management with cryptographic integrity verification
  - Cross-platform screenshot capture
  - Log sanitization and anti-forensics utilities

</details>

---

## Documentation & Support

### Community

Join our Discord server for real-time discussions, technical support, and the latest updates on emp3r0r development.

### Resources

- 📸 [Screenshots and Videos](./Screenshots.md) - Visual demonstrations of emp3r0r's capabilities
- 📋 [Features Overview](./FEATURES.md) - Comprehensive feature documentation
- 📝 [Security Policy](./SECURITY.md) - Security guidelines and vulnerability reporting
- 📜 [Changelog](./CHANGELOG.md) - Version history and recent updates

### Troubleshooting

**Common Issues:**

- **Connection stalls**: Verify C2 host IP/domain configuration and WireGuard settings
- **Compatibility issues**: Remove `~/.emp3r0r` directory for a clean installation
- **Feature questions**: Use built-in command-line help for up-to-date information

> **Note**: Cross-version compatibility is not guaranteed due to active development. Always check release notes for breaking changes.

---

## Support Development

If emp3r0r has proven valuable in your security research and testing, consider supporting its continued development:

Your sponsorship directly enables:

- **Accelerated Development** of new post-exploitation techniques and features
- **Security Maintenance** with regular updates and rapid vulnerability patching
- **Documentation Excellence** including comprehensive guides and video tutorials
- **Community Support** with faster issue resolution and feature requests
- **Research & Innovation** in advanced evasion and stealth technologies

Every contribution, regardless of size, helps keep emp3r0r actively maintained, secure, and evolving.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
