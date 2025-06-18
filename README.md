<div align="center">
  
# emp3r0r

![emp3r0r Banner](./assets/logos/banner.svg)

**An advanced post-exploitation framework designed for Linux/Windows environments**

[![Discord](https://img.shields.io/badge/Discord-Join%20Server-7289da?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/vU98aQtk9f)
[![GitHub Sponsors](https://img.shields.io/badge/GitHub-Sponsor-ff69b4?style=for-the-badge&logo=github&logoColor=white)](https://github.com/sponsors/jm33-m0)
[![Screenshots](https://img.shields.io/badge/View-Screenshots-blue?style=for-the-badge)](./Screenshots.md)

---

</div>

## 🚀 Quick Start

Get emp3r0r running in minutes with our streamlined installation and setup process.

### Installation

```bash
curl -sSL https://raw.githubusercontent.com/jm33-m0/emp3r0r/refs/heads/v3/install.sh | bash
```

### 3-Step Setup

#### 1️⃣ Start the Server

```bash
emp3r0r server --c2-hosts 'your.domain.com' --port 12345 --operators 2
```

This command initiates emp3r0r with:

- HTTP2/TLS agent listener on random port with valid hostname in TLS certificate
- WireGuard operator service on specified port (12345)
- Operator mTLS server on `wg_ip:12346`
- Pre-registered operator slots (2 in this example)

The server displays:

1. **WireGuard Server Configuration** - server IP, port, and public key
2. **WireGuard Operator Configurations** - each operator's credentials
3. **Client Connection Commands** - ready-to-use commands

#### 2️⃣ Connect as Operator

Copy the generated connection command and replace `<C2_PUBLIC_IP>` with your server's IP:

```bash
emp3r0r client --c2-port 12345 --server-wg-key 'key...' --c2-host your.domain.com
```

**Connection Process:**

- Each operator receives a unique, pre-configured connection command
- For local testing: use `127.0.0.1` as the C2 host
- For remote connections: replace `<C2_PUBLIC_IP>` with your server's public IP or domain
- System prompts for operator's private key (displayed in server configuration)
- WireGuard connectivity is automatically configured

#### 3️⃣ Generate Agent Payloads

Use the `generate` command from within the emp3r0r shell interface.

---

## 💡 What is emp3r0r?

emp3r0r is a comprehensive post-exploitation framework that stands out as one of the first C2 frameworks purpose-built for Linux environments while providing seamless Windows integration. Originally developed as a research project for implementing Linux adversary techniques, it has evolved into a robust framework addressing the need for advanced post-exploitation capabilities.

### Key Differentiators

- **Linux-First Design**: Purpose-built for Linux targets with extensive Windows support
- **Extensible Architecture**: Complete Python3 support via the `vaccine` module (15MB) including Impacket, Requests, and MySQL
- **Diverse Module Support**: Bash, PowerShell, Python, DLL, SO, and EXE modules
- **Advanced Evasion**: Dynamic process obfuscation and file concealment capabilities

---

## ✨ Core Features

<details>
<summary><strong>🔐 Security & Stealth</strong></summary>

- **Advanced Evasion**

  - Dynamic `argv` manipulation for process listing obfuscation
  - File and PID concealment through Glibc hijacking
  - Anti-analysis capabilities

- **Secure Communications**
  - HTTP2/TLS-based command and control
  - UTLS implementation to defeat JA3 fingerprinting
  - KCP-based fast, multiplexed UDP tunneling
  - TOR and CDN proxy support
  - WireGuard + mTLS operator connections

</details>

<details>
<summary><strong>🖥️ User Experience</strong></summary>

- **Advanced CLI Interface**

  - Built on console and cobra frameworks
  - Comprehensive auto-completion with syntax highlighting
  - Multi-tasking through tmux integration
  - Bring Your Own Shell functionality (elvish support)

- **Enhanced Shell Experience**
  - SSH integration with PTY support
  - Windows compatibility with standard SSH clients
  - SFTP integration for remote file access

</details>

<details>
<summary><strong>🌐 Network Capabilities</strong></summary>

- **Network Traversal**
  - Automatic agent bridging via Shadowsocks proxy chain
  - Reverse proxy through SSH and KCP tunneling
  - External target access for unreachable endpoints
  - Bidirectional port mapping (TCP/UDP)
  - Agent-side Socks5 proxy with UDP support

</details>

<details>
<summary><strong>🔧 Payload & Execution</strong></summary>

- **Flexible Payload Delivery**

  - Multi-stage delivery for Linux and Windows
  - HTTP Listener with AES encryption and compression
  - DLL agent, Shellcode agent (Windows)
  - Shared Library stager (Linux)

- **In-Memory Execution**
  - Bash, PowerShell, Python, and ELF binaries
  - CGO ELF loader for memory-only execution
  - Process and shellcode injection
  - ELF binary patching for persistence

</details>

<details>
<summary><strong>🎯 Post-Exploitation</strong></summary>

- **Memory Forensics**

  - Cross-platform memory dumping
  - Windows mini-dump extraction (pypykatz compatible)

- **Additional Capabilities**
  - Bettercap integration
  - Multiple persistence mechanisms
  - OpenSSH credential harvesting
  - Privilege escalation tools and suggestions
  - System information collection
  - File management with integrity verification
  - Screenshot functionality
  - Log sanitization utilities

</details>

---

## 📖 Documentation & Support

### 💬 Community

Join our Discord server for discussions, support, and updates!

### 📚 Resources

- 📸 [Screenshots and Videos](./Screenshots.md) - Visual guide to emp3r0r's capabilities
- 📋 [Features Overview](./FEATURES.md) - Comprehensive feature list
- 📝 [Security Policy](./SECURITY.md) - Security guidelines and reporting
- 📜 [Changelog](./CHANGELOG.md) - Recent updates and changes

### 🐛 Troubleshooting

**Common Issues:**

- **Connection stalls**: Verify C2 host IP/domain and WireGuard configuration
- **Compatibility issues**: Remove `~/.emp3r0r` directory and start fresh
- **Feature questions**: Use command-line help for current information

> **Note**: Cross-version compatibility is not guaranteed due to ongoing development. Check release logs for breaking changes.

---

## 🤝 Support the Project

If emp3r0r has been helpful in your work, please consider supporting its development:

Your sponsorship helps:

- 🚀 **Accelerate development** of new features and improvements
- 🛡️ **Maintain security** with regular updates and vulnerability fixes
- 📚 **Improve documentation** and create better learning resources
- 🔧 **Provide community support** and respond to issues faster
- 💡 **Research and innovation** in post-exploitation techniques

Every contribution, no matter the size, makes a difference in keeping emp3r0r actively maintained and evolving!

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
