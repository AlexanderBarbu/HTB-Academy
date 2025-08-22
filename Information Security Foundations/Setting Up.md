# Introduction
## Penetration Testing Stages & Situations

- **Engagement Variability**: Scope, results, environment differ per client.  
- **Internal Pentest**: Usually given internal host with internet → need VPS for tools/resources.  
- **Remote Testing**:  
  - Ship preinstalled device.  
  - Provide VM calling back to infra (OpenVPN).  
  - Client-hosted image → SSH + customization.  
  - VPN access directly → use local Linux & Windows VMs.  
- **On-Site Testing**:  
  - Bring up-to-date Linux & Windows VMs.  
  - Linux → tool support.  
  - Windows → easier AD enumeration.  
- **Key Principle**: Be versatile & adaptable, guide client to optimal solution.  
- **Day 1 Prep**: Fully tooled & structured VMs → minimize wasted time.  

## Setup & Efficiency

- **Structured Setup**: Organized, prebaked, reproducible → faster engagements.  
- **Pitfalls**:  
  - Too many tools → bloat, slowdowns.  
  - Info overload → 50 different “best setups”.  
  - Migration challenges when switching environments.  
- **Best Practice**:  
  - Build **personal, minimal, adaptable environment**.  
  - Know it inside out, configure & adapt independently.  
- **Efficiency**:  
  - Avoid searching for dependencies mid-engagement.  
  - Prepared environments = focus on assessment, not setup.
---
# Organization

### Why Organization Matters
- Saves time navigating environment & finding resources.  
- Corporate networks = heterogeneous (Linux/Windows hosts).  
- Organize by **OS** and **pentest stage**.  
- Teams need common structure to avoid lost/corrupted evidence.  
- Start small → OS-based org is best for beginners.  

### Example Structures
**By OS & Stage**

Penetration-Testing/
├── Pre-Engagement/ 
├── Linux/
├── Information-Gathering/
├── Vulnerability-Assessment/
├── Exploitation/
├── Post-Exploitation/
└── Lateral-Movement/
├── Windows/ (same subfolders as Linux)
├── Reporting/
└── Results/

**By Field (Network/WebApp/Social Eng.)**  

Penetration-Testing/  
├── Pre-Engagement/  
├── Network-Pentesting/  
├── Linux/...  
├── Windows/...  
├── WebApp-Pentesting/  
├── Social-Engineering/  
├── Reporting/  
└── Results/

---

## Bookmarks
- Use Firefox account sync → add-ons & bookmarks auto-sync.  
- **Rule**: Assume third parties may see your bookmarks.  
- Never store sensitive customer data.  
- Maintain **separate pentesting account** for bookmarks.  
- For edits, keep list locally & import.  

## Password Managers
- **Password issues**:  
  1. Complexity → hard to create/remember.  
  2. Reuse → same password across services.  
  3. Memory → multiple creds = mixups.  
- **Solution**: Password managers (complex, unique creds).  
- Popular tools: 1Password, LastPass, Keeper, Bitwarden, Proton Pass.  
- **Proton Pass** → free + paid plans, 2FA, secure vault, dark web monitoring.  
- Only 1 master password to manage everything.  

## Updates & Automation
- Always update OS, tools, GitHub repos before new pentest.  
- Keep list of resources & sources → easier automation.  
- Automation via Bash, Python, PowerShell scripts.  
- Store scripts on Proton, GitHub, or self-hosted server.  
- Benefit: faster reinstall/setup, scripting practice, process efficiency.  

## Note Taking
**Types of Info**:  
1. **Discovered Information**: IPs, users, creds, code (from OSINT, scans, analysis).  
2. **Ideas / Processing**: future tests, overlooked vulns, next steps.  
   - Tools: Notion, Anytype, Obsidian, Xmind.  
3. **Results**: scan findings & test data (keep everything → may be useful later).  
   - Tools: GhostWriter, Pwndoc.  
4. **Logging**: proof of actions, defense if 3rd-party causes damage.  
   - Tools: `date`, `script` (Linux), `Start-Transcript` (Windows).  
   - Use naming format: `<date>-<time>-<phase>.log`.  
   - Terminal emulators (Tmux, Ghostty) can log automatically.  
   - If tool lacks logging → use redirection (`>>`, `tee`, `Out-File`).  
1. **Screenshots**: Evidence & Proof of Concept.  
   - Tools: Flameshot (screenshots), Peek (GIF recordings).  

>[!NOTE]
> **Organize everything** (folders, bookmarks, creds, notes).  
>  **Automate & update** often → no wasted time.  
>  **Record all steps** (logs, screenshots, notes).  
>  Efficiency & structure = smoother pentests + stronger reports.  

---
# Virtualisation

- **Definition**: Abstraction of physical computing resources (hardware/software) into virtual/logical components.  
- **Purpose**:  
  - Abstraction layer → independence from physical form.  
  - Better resource utilization, flexibility, and scalability.  
  - Run applications on systems that normally wouldn’t support them.  
- **Types**:  
  - Hardware Virtualization (VMs via hypervisor).  
  - Application Virtualization.  
  - Storage Virtualization.  
  - Data Virtualization.  
  - Network Virtualization.  
- **Hypervisor**: Allocates host hardware → runs guest VMs.  
- **Guest Additions (VirtualBox)**: Drivers & tools for better VM performance and usability.  
---
## Virtual Machines (VMs)
- **Definition**: Virtual OS running on a physical host. Multiple isolated VMs can run in parallel.  
- **Managed by**: Hypervisor (allocates CPU, RAM, disk, NIC).  
- **Behavior**: Guest OS/applications believe they run on physical hardware.  
- **Disadvantage**: Slight performance loss due to virtualization overhead.  
- **Advantages**:  
  - Isolation: VMs don’t interfere with each other.  
  - Independence: Guest system independent from host OS/hardware.  
  - Portability: Easy move/clone by copying.  
  - Dynamic resource allocation.  
  - Efficient hardware utilization.  
  - Fast provisioning & simplified management.  
  - High availability (not tied to single hardware instance).  
---
## VirtualBox
- **Alternative to VMware Workstation Pro (free, open-source).**  
- **Disk Formats**:  
  - VDI (native).  
  - VMDK (VMware), VHD (Microsoft), others.  
  - Conversions possible with `VBoxManage`.  
- **Installation**:  
  - Download from [virtualbox.org](https://www.virtualbox.org).  
  - Or on Ubuntu:  
```bash
sudo apt install virtualbox virtualbox-ext-pack -y
```
- **Extension Pack Features**:  
  - USB 2.0/3.0 support.  
  - VirtualBox RDP.  
  - Disk encryption.  
  - PXE Boot.  
  - NVMe support.  
- **Use Case**: Simple, quick private use; supports multiple VM formats; easily configurable.  
---
## Proxmox

- **Definition**: Open-source, enterprise-grade virtualization & management platform.  
- **Technology**:  
  - KVM → full virtualization.  
  - LXC → container-based virtualization.  
- **Solutions**:  
  - Proxmox Virtual Environment (VE).  
  - Proxmox Backup Server.  
  - Proxmox Mail Gateway.  
- **Usage**:  
  - Build/simulate entire networks with VMs & containers.  
  - Install via ISO image (e.g., Proxmox VE 8.4).  
  - Can be tested inside VirtualBox VM (allocate ≥4GB RAM, 2 CPUs).  
- **Setup Steps**:  
  1. Download ISO.  
  2. Create VM in VirtualBox, attach ISO.  
  3. Assign resources (CPU, RAM, storage, network).  
  4. Install Proxmox VE → login with `root:<password>`.  
  5. Access management dashboard via provided web URL.  
- **Dashboard (Datacenter)**:  
  - Upload/manage VMs and containers.  
  - Configure networks and storage.  
  - Centralized monitoring (disk, memory, CPU usage).  

---

>[!NOTE]
	> - Virtualization = core of modern IT + pentesting labs.  
	> - VMs offer isolation, portability, flexibility, and efficient resource usage.  
	> - VirtualBox = free, flexible tool for personal labs.  
	> - Proxmox = enterprise-level virtualization, also usable for home/small-scale lab environments.  

---
# Backups and Recovery

### Importance
- Safeguard against **data loss, compromise, business interruption**.  
- Viewed from two angles:  
  - **Defense** → protection & resilience.  
  - **Attack Target** → backups often high-value target.  
- Examples:  
  - Colonial Pipeline (2021): ransomware, recovery relied on isolated backups.  
  - Equifax (2017): poor incident response worsened breach.  
- Key factor: **speed & accuracy of recovery** → determines business continuity.  

---

### Pika Backup
- GUI-based, user-friendly.  
- Features:  
  - Incremental backups (only new/changed files).  
  - Encryption (AES-256-CTR).  
  - Local or remote storage.  
  - Based on BorgBackup repositories (encrypted, deduplicated archives).  
- **3-2-1 Rule**:  
  - 3 copies of data.  
  - 2 different devices.  
  - 1 offsite.  
- Setup:  
  - `sudo apt install flatpak` + `flatpak install org.gnome.World.PikaBackup`.  
  - Configure repo location (e.g. HDD), set encryption passphrase.  
  - Choose directories (e.g. home dir, exclude caches).  
  - Configure schedule (daily recommended).  
  - Run integrity checks to validate archives.  

---

### Duplicati
- Cross-platform backup solution (web-based management).  
- Features:  
  - AES-256 encryption (optionally GPG/RSA).  
  - Client-side encryption, password-based key derivation.  
  - Wide destination support: Google Drive, OneDrive, S3, SFTP, Dropbox, etc.  
- Installation:  
  - Download `.deb` package → `sudo apt install ./duplicati-x.deb`.  
  - Run → access via `http://localhost:8200`.  
- Setup:  
  - Add backup → set name, encryption, passphrase.  
  - Destination: SFTP with SSH keys (`ssh-keygen -t ed25519`).  
  - Configure remote server IP, path, username, authentication method.  
  - Source data selection with regex filtering.  
  - Configure backup schedule (daily recommended).  

---

### Best Practices
- Encrypt backups **at rest and in transit** (compliance: GDPR, HIPAA).  
- Keep backups isolated from production environment.  
- Document and test **disaster recovery plans**:  
  - Simulate full recovery (server failure, data loss).  
  - Perform at least twice a year (preferably quarterly).  
  - Record step-by-step for repeatability and continuity planning.  

---

>[!IMPORTANT]
> -  Backups = critical defense + frequent attack target.  
> - **Pika Backup** → simple GUI, local/remote, deduplication.  
> - **Duplicati** → advanced, remote storage support, strong encryption.  
> - **Recovery > Backup** → ability to restore quickly is what matters most.  
> - Regular testing of recovery ensures resilience under real-world incidents. 

---
# Server Management, Password & Secret Management, Git Hosting

## Server Management
- **Goals**: fast, reliable, secure server with adequate resources.  
- **Access First**: lock down access **before** enabling services → allow **one** secure entry (SSH with key auth only).  
- **Zero Trust**: no implicit trust (inside/outside); grant least-privilege access.  
- **Scale mgmt**: for many servers use **Teleport** (+ SSO, audit) and **Ansible** (config as code).
#### SSH Hardening (Ubuntu/Debian)
- Edit `/etc/ssh/sshd_config` (recommended baseline):
```
    PermitRootLogin no  
    PubkeyAuthentication yes  
    PasswordAuthentication no  
    X11Forwarding no  
    Port 4444  
    AllowUsers cry0l1t3
```

- Apply changes:
```
    sudo service ssh restart
```
- Generate strong key (client):
```
    ssh-keygen -t ed25519 -f ~/.ssh/cry0l1t3
```
- Server: add public key to `~/.ssh/authorized_keys` and secure perms:
```
    chmod 600 ~/.ssh/authorized_keys
```
- Load key into agent & define host alias:
```
    ssh-add ~/.ssh/cry0l1t3  
    # ~/.ssh/config
    Host MyVPS
        HostName <IP-or-domain>
        IdentityFile ~/.ssh/cry0l1t3
        Port 4444
        User cry0l1t3
        IdentitiesOnly yes
```
- Start agent & connect with alias:
```
    eval $(ssh-agent)  
    ssh MyVPS
    
```
---

## Password & Secret Management
- **Why**: eliminate weak/reused passwords; centralize & encrypt secrets.  
- **Good choices**: Proton, Bitwarden, 1Password, Passbolt, Psono, Passky, OpenBao.  
- **Encryption models**:
  - **E2EE** (most): only user devices decrypt.
  - **Psono**: client‑side encryption (encrypt before send).
  - **Passbolt**: GPG (public/private keys).
- **Self‑hosting**: Linode Marketplace images (e.g., OpenBao/HashiCorp Vault, Passbolt CE, Passky) for quick deploys.

---

## Git Hosting
- **What**: DVCS to track changes, collaborate, branch/merge, and roll back.  
- **Use cases**:
  - CI/CD releases; quick rollback on breakage.
  - Parallel feature development via branches.
  - Private repos for **dotfiles** (bootstrap new VMs fast).
- **Providers**: GitHub, GitLab, Bitbucket, **Gitea**, OneDev.  
- **Self‑host**: Gitea/GitLab available as preconfigured images (e.g., on Linode).

---

## Key Takeaways
- Lock down servers **first** (SSH key‑only, no passwords), apply **Zero Trust**.  
- Use a password/secret manager with strong crypto; prefer self‑hosting for sensitive ops.  
- Manage fleets with **Teleport** (access/audit) + **Ansible** (automation).  
- Treat configs as code (Git) and version your environment (dotfiles) for repeatable setup.

---
# Network Security

## Importance
- Core part of cybersecurity → defines **access rules**.  
- Once hardened, requires **constant monitoring** to maintain security.  
- Needs to balance **security + efficiency**.  

---

## Zero Trust Network Access (ZTNA)
- **Definition**: Modern framework → replaces traditional perimeter models (VPN).  
- **Principle**: *Never trust, always verify*.  
- **Mechanism**:  
  - Authenticate & authorize **every user, device, and connection**.  
  - Decisions based on **identity, context, device status, security posture**.  
  - Granular resource access instead of broad group/network access.  
- **Pros**: Stronger security.  
- **Cons**: Complexity in managing all devices/resources.  

---

## Providers
- **Netbird**  
  - Open-source, WireGuard-based **P2P mesh**.  
  - Ideal for hybrid/distributed setups (remote work, servers, branch offices).  
  - Supports self-hosting.  
  - Use Case: connecting dev workstations to private repos.  
- **Tailscale**  
  - WireGuard-based virtual private cloud.  
  - Minimal configuration.  
  - Use Case: secure remote employee connections (CI/CD, dashboards) or site-to-site links w/o firewall complexity.  
- **Twingate**  
  - Relay + Connector architecture, API-first.  
  - Ideal for securing **databases, Kubernetes clusters, legacy apps** in multi-cloud or on-prem.  

---

## Recommendations
- Each provider offers free trials → test based on **network design + use case**.  
- Philosophies differ:  
  - **Netbird** → open-source, P2P, hybrid infra.  
  - **Tailscale** → simplicity, minimal config, remote workers.  
  - **Twingate** → enterprise-grade, API-centric, complex infra.  
- For this module: **Netbird** chosen (self-hosting + flexibility).  

---

## Key Takeaways
- Network security is critical → restrict access first, then monitor continuously.  
- ZTNA → replaces VPNs with identity/context-based access.  
- Choice of provider depends on **infrastructure + goals**.  
- Netbird is preferred here due to **open-source + self-hosting** capabilities.  
