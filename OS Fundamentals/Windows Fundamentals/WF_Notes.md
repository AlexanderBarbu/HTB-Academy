## Accessing Windows

## Table of Contents
- [Start WMI interactive shell](#start-wmi-interactive-shell)
- [Run WMI command directly](#run-wmi-command-directly)
    - [Microsoft Management Console (MMC)](#microsoft-management-console-mmc)
    - [Key Features](#key-features)
    - [What Are Snap-ins?](#what-are-snap-ins)
    - [How to Open](#how-to-open)
- [Run from Start or Run dialog](#run-from-start-or-run-dialog)
  - [Windows Subsystem for Linux (WSL)](#windows-subsystem-for-linux-wsl)
    - [WSL 2](#wsl-2)
    - [Instalation](#instalation)
  - [What is Hyper-V](#what-is-hyper-v)
    - [Definition](#definition)
    - [What Can Hyper-V Do?](#what-can-hyper-v-do)
    - [Use in WSL 2](#use-in-wsl-2)
    - [Enabling Hyper-V](#enabling-hyper-v)
  - [Desktop Experience vs. Server Core](#desktop-experience-vs-server-core)
    - [Key Differences](#key-differences)
    - [GUI Tools Still Available in Server Core](#gui-tools-still-available-in-server-core)
    - [⚙️ Setup with `Sconfig`](#️-setup-with-sconfig)
    - [Applications Not Supported on Server Core](#applications-not-supported-on-server-core)
    - [Summary](#summary)
    - [Feature Comparison Table](#feature-comparison-table)
- [Windows Security](#windows-security)
  - [Security Principles](#security-principles)
  - [Security Identifier (SID)](#security-identifier-sid)
    - [Example](#example)
  - [USER INFORMATION](#user-information)
    - [SID Structure](#sid-structure)
    - [Security Accounts Manager (SAM) and Access Control Entries (ACE)](#security-accounts-manager-sam-and-access-control-entries-ace)
    - [User Account Control (UAC)](#user-account-control-uac)
      - [Admin Approval Mode](#admin-approval-mode)
      - [Why It Matters](#why-it-matters)
  - [Registry](#registry)
    - [Structure](#structure)
    - [Root Keys](#root-keys)
    - [Registry Value Types](#registry-value-types)
    - [Example: Registry Editor UI](#example-registry-editor-ui)
  - [Application Whitelisting](#application-whitelisting)
    - [Key Concepts](#key-concepts-1)
    - [Benefits of Whitelisting](#benefits-of-whitelisting)
  - [AppLocker](#applocker)
    - [Features](#features)
    - [Rule Types](#rule-types)
  - [Local Group Policy](#local-group-policy)
    - [Domain vs Local Group Policy](#domain-vs-local-group-policy)
    - [What Can Be Configured?](#what-can-be-configured)
- [Windows Defender Antivirus](#windows-defender-antivirus)
  - [History](#history)
  - [Key Features](#key-features-1)
  - [Configuration \& Management](#configuration--management)
  - [UI Example](#ui-example)


### Local Access
If you are reading these words, you have local access to a computer of some kind — smartphone, tablet, laptop, Raspberry Pi, or desktop.  
Local access is the most common way to access any computer, including Windows systems.  
- Input happens through keyboard, trackpad, or mouse  
- Output comes from the display screen  

Organizations typically build security policies and controls around employees using dedicated, org-owned computers on-premise.  
Remote work is increasingly common, but local access still matters, especially for technical professionals who may work on multiple machines daily.

---

### Remote Access
Remote access means accessing a computer over a network.  
- Local access is needed first before you can initiate remote access  
- Used widely in IT, dev, and security work  

Common remote access methods:
- **Virtual Private Networks (VPN)**
- **Secure Shell (SSH)**
- **File Transfer Protocol (FTP)**
- **Virtual Network Computing (VNC)**
- **Windows Remote Management (WinRM)**
- **Remote Desktop Protocol (RDP)** → Focus in this module  

Remote access enables:
- Centralized management
- Standardization of technology
- Automation of tasks
- Remote work arrangements
- Quick response to issues or security threats  

Industries like **MSPs** (Managed Service Providers) and **MSSPs** (Managed Security Service Providers) rely heavily on remote access.

---

### Remote Desktop Protocol (RDP)
- RDP uses client/server architecture  
- Client specifies target IP/hostname where RDP is enabled  
- Server = target machine  
- Default port: **3389**  

Think of it as:
- **Subnet = street**
- **IP = house**
- **Port = window/door**

Request (inside packet) → reaches IP → directed to app on specified port.  
IP addressing + protocol encapsulation covered deeper in *Introduction to Networking* module.

---

### Remote Desktop Connection (RDC)
Built-in Windows RDP client: `mstsc.exe`  
- Used to connect to target IP/hostname via port 3389  
- Allows saving connection profiles and credentials (admins often do this)  
- Saved `.rdp` files can be valuable during engagements  

*To use RDC:*
- Run `mstsc`
- Enter target IP or hostname
- Optionally save connection profile  

Remote access must be enabled on target (default: it's disabled).  
HTB Academy labs are pre-configured for RDP access via VPN.

---

### Using xfreerdp
Popular RDP client on Linux (used often in HTB modules)  
- CLI utility, supports file transfer, clipboard, display options  

Example:
```bash
xfreerdp /u:<username> /p:<password> /v:<target_ip>

---

## Operating System Structure

### Root directory
- Root dir = `<drive_letter>:\` (commonly `C:\`)
- OS installed in the **boot partition**
- Other drives (physical/virtual) get other letters, e.g. `E:\` for data drives

---

### Main directories
| Directory | Function |
|------------|----------|
| Perflogs | Holds Windows performance logs (empty by default) |
| Program Files | 16/32-bit apps on 32-bit systems; 64-bit apps on 64-bit systems |
| Program Files (x86) | 16/32-bit apps on 64-bit systems |
| ProgramData | Hidden; essential app data accessible by all users |
| Users | User profiles (includes Public, Default) |
| Default | Template profile for new users |
| Public | Shared folder for all users; shared on network by default |
| AppData | Per-user hidden app data → subfolders: Roaming, Local, LocalLow |
| Windows | Core Windows OS files |
| System / System32 / SysWOW64 | DLLs for Windows core features / API |
| WinSxS | Component Store (copies of components, updates, service packs) |

---

### Exploring directories via command line

#### Using `dir`
Example:
```powershell
dir c:\ /a

## File System

### Windows file systems
There are 5 types:
- **FAT12**
- **FAT16**
- **FAT32**
- **NTFS**
- **exFAT**

➡️ **FAT12** & **FAT16**: obsolete  
➡️ **Main focus**: NTFS (modern default), but FAT32 & exFAT are still relevant in certain contexts  

---

### FAT32
Pros:
- Great device compatibility (computers, cameras, consoles, smartphones, tablets)  
- OS cross-compatibility (Windows 95+, macOS, Linux)

Cons:
- Max file size: **<4GB**
- No built-in data protection / compression
- No native encryption (needs 3rd-party tools)

---

### NTFS
Default since **Windows NT 3.1**  
Pros:
- Reliable (can restore FS consistency after failure)
- Supports granular permissions
- Very large partition support
- Journaling (logs file changes)

Cons:
- Not natively supported by most mobile devices
- Limited support by older media devices (e.g. TVs, cameras)

---

### NTFS Permissions

| Permission Type | Description |
|-----------------|-------------|
| Full Control | Read, write, change, delete |
| Modify | Read, write, delete |
| List Folder Contents | View/list folders + execute files (folders only inherit this) |
| Read and Execute | View/list files + execute |
| Write | Add files / write to files |
| Read | View/list folders and file contents |
| Traverse Folder | Move through folders to reach a file (even without listing/view perms on intermediate folders) |

By default:
- Files/folders inherit perms from parent  
- Admins can disable inheritance + set custom perms  

---

### Managing permissions with `icacls`

We can view/manage NTFS perms via:
- **GUI** (File Explorer → Security tab)  
- **CLI:** `icacls`

#### Example: list permissions
```powershell
icacls c:\windows

### Further Reading: icacls

For a full reference on `icacls` syntax, options, and examples:  
➡️ [icacls command documentation (ss64.com)](https://ss64.com/nt/icacls.html)

### EternalBlue (had to google it)
- CVE-2017-0144 (SMBv1 remote code execution vuln)
- Exploit: crafted SMB packets → kernel-level code execution
- Linked to: NSA (leaked by Shadow Brokers)
- Famously used in: WannaCry, NotPetya
- Mitigation: Disable SMBv1, apply MS17-010, segment SMB traffic

## NTFS vs. Share Permissions

### Context
- Windows είναι high-value target λόγω τεράστιου market share → malware authors το προτιμούν  
- Malware + ransomware (π.χ. μέσω **EternalBlue**) συχνά εκμεταλλεύονται **lenient network share permissions**  
- SMB (Server Message Block) → πρωτόκολλο για file/printer sharing σε Windows  

---

### Share permissions

| Permission | Description |
|------------|-------------|
| Full Control | All actions (change, read) + change NTFS perms |
| Change | Read, edit, delete, add files/folders |
| Read | View files & subfolders |

---

### NTFS basic permissions

| Permission | Description |
|------------|-------------|
| Full Control | Add, edit, move, delete + change NTFS perms |
| Modify | View, modify, add, delete |
| Read & Execute | View contents, run programs |
| List folder contents | View file/subfolder listing |
| Read | View file contents |
| Write | Write changes, add new files |
| Special Permissions | Advanced permission options |

---

### NTFS special permissions

| Permission | Description |
|------------|-------------|
| Full Control | Same as basic full control |
| Traverse folder / execute file | Access subfolders / run programs even without parent access |
| List folder / read data | View folder contents / open files |
| Read attributes | View basic attributes (system, archive, etc) |
| Read extended attributes | View app-specific attributes |
| Create files / write data | Create files + modify content |
| Create folders / append data | Create subfolders, add to files (no overwrite) |
| Write attributes | Change basic attributes |
| Write extended attributes | Change extended attributes |
| Delete subfolders/files | Delete content without deleting parent folder |
| Delete | Delete folder + content |
| Read permissions | View permission settings |
| Change permissions | Change permission settings |
| Take ownership | Become owner of file/folder |

---

### Key concepts
- **NTFS perms** apply locally (on the system where files/folders live)  
- **Share perms** apply when accessing via SMB (over network)  
- NTFS perms = more granular, detailed control  
- NTFS folders inherit parent perms by default → can disable inheritance for custom perms  

Someone accessing locally (e.g. console, RDP) only deals with **NTFS perms**.  
Someone accessing over network (SMB) → both **share + NTFS perms** apply.

## Network Shares and Permissions

### Malware & Windows
- Windows = high-value target (70%+ market share)
- Malware authors focus on Windows → wider reach
- No OS is immune; any OS can have malware
- **EternalBlue (SMBv1)** still a major threat on unpatched systems → common path for ransomware

---

### SMB (Server Message Block)
- Protocol for sharing resources (files, printers) over network
- Used across org sizes (SMB = Small/Medium/Large business)

---

### Share vs NTFS Permissions
They apply together on shared resources but are not the same:
- **NTFS permissions** → apply locally (on file system)
- **Share permissions** → apply when accessing over SMB (network)

---

### Share Permissions

| Permission | Description |
|------------|-------------|
| Full Control | All Change + Read actions + change NTFS perms |
| Change | Read, edit, delete, add files/folders |
| Read | View file and subfolder contents |

---

### NTFS Basic Permissions

| Permission | Description |
|------------|-------------|
| Full Control | Add/edit/move/delete + change perms |
| Modify | View/modify/add/delete |
| Read & Execute | View + run programs |
| List folder contents | View files/subfolders |
| Read | View contents |
| Write | Write changes + add files |
| Special Permissions | Advanced options |

---

### NTFS Special Permissions

| Permission | Description |
|------------|-------------|
| Full Control | Same as basic full control |
| Traverse folder / execute file | Access subfolders/run programs without parent folder access |
| List folder/read data | View folder content + open files |
| Read attributes | View basic file/folder attributes |
| Read extended attributes | View app-specific attributes |
| Create files/write data | Create files + edit content |
| Create folders/append data | Create subfolders + add data (no overwrite) |
| Write attributes | Change basic attributes |
| Write extended attributes | Change extended attributes |
| Delete subfolders and files | Delete content but not parent |
| Delete | Delete parent + content |
| Read permissions | View permission settings |
| Change permissions | Modify permission settings |
| Take ownership | Become owner of file/folder |

---

### Key points
- NTFS perms apply on local system (incl. RDP access)
- Share perms apply over SMB (remote access)
- NTFS gives more granular control
- NTFS folders inherit parent perms by default (can disable inheritance)

---

## Creating and Managing a Network Share

### Context
- Created shared folder (e.g. `Company Data`) on Windows 10 Desktop using GUI → **Advanced Sharing**
- Shares on desktop OS = small biz / beachhead / attacker exfil
- Enterprise shares = SAN / NAS / Windows Server

---

### Share setup summary
- **Share name** defaults to folder name
- Possible to set max concurrent users
- Permissions: both **SMB (share)** + **NTFS** apply
- Share ACL → list of **ACEs** (Access Control Entries) → users/groups (security principals)

---

### Share types seen
| Sharename | Type | Comment |
|-----------|------|---------|
| ADMIN$ | Disk | Remote Admin |
| C$ | Disk | Default share |
| Company Data | Disk | (our custom share) |
| IPC$ | IPC | Remote IPC (inter-process comms pipe) |

---

### Commands used
List shares:
-> bash
smbclient -L <target_IP> -U htb-student

smbclient '\\<target_IP>\Company Data' -U htb-student

---

## Service Permissions

### Key points
- Services = long-running processes, critical to Windows  
- Often overlooked → potential for:
  - Loading malicious DLLs
  - App execution w/o admin rights
  - Privilege escalation
  - Persistence  

- Misconfigs happen due to:
  - 3rd party software installers
  - Admin mistakes  

- Critical services should run under dedicated **service accounts** (not regular user accounts)

---

### Built-in service accounts
- **LocalSystem** → highest local privilege
- **LocalService** → minimal local privilege
- **NetworkService** → minimal local + network identity  

*Principle of Least Privilege* → services should not run with more rights than needed.

---

### Managing/viewing services

**GUI**
- `services.msc`
  - View name, path, logon account, recovery actions
  - Example: `Windows Update (wuauserv)`

**CLI: `sc.exe`**
- Query config:
```powershell
sc qc wuauserv

---

## Understanding SDDL in Service Permissions

### What is SDDL?
- **SDDL (Security Descriptor Definition Language)** → format used to represent security descriptors in Windows
- Every securable object (even unnamed ones) has a **security descriptor**
- A security descriptor contains:
  - **Owner**
  - **Primary group**
  - **DACL (Discretionary Access Control List)** → controls access
  - **SACL (System Access Control List)** → logs access attempts

---

### Example SDDL (from wuauserv service)

Breakdown:
- `D:` → indicates this string defines a DACL  
- Each `( ... )` → Access Control Entry (ACE) for a user/group  

---

#### First ACE: `(A;;CCLCSWRPLORC;;;AU)`
- `A;;` → Access is **Allowed**
- `;;;AU` → Applies to **Authenticated Users**
- Permissions:
  - `CC` → SERVICE_QUERY_CONFIG (query service config)
  - `LC` → SERVICE_QUERY_STATUS (query service status)
  - `SW` → SERVICE_ENUMERATE_DEPENDENTS (list dependent services)
  - `RP` → SERVICE_START (start service)
  - `LO` → SERVICE_INTERROGATE (query current status)
  - `RC` → READ_CONTROL (read security descriptor)

---

#### Second ACE: `(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)`
- Applies to **Builtin Administrators (BA)**
- Broader permissions including:
  - `WP` → SERVICE_STOP
  - `DT` → SERVICE_PAUSE_CONTINUE
  - `SD` → DELETE
  - `WD` → WRITE_DAC
  - `WO` → WRITE_OWNER  
  *(plus those from first ACE)*  

---

#### Third ACE: `(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)`
- Applies to **SYSTEM**
- Same extensive permissions as BA  

---

### Notes
- The structure:  

(A;; <permissions> ;;; <security principal>)

- Each 2-char code → specific right  
- DACL controls what users/groups can do  
- SACL (not shown here) would log attempts  

---

## Windows Sessions

### Interactive Sessions
- Initiated by a user entering credentials (local or domain)
- Methods:
  - Direct login at machine
  - `runas` command (secondary logon session)
  - Remote Desktop (RDP)

---

### Non-Interactive Sessions
- No login credentials required  
- Used by Windows to start services, apps, scheduled tasks at boot  
- Accounts:  
  - **Local System (NT AUTHORITY\SYSTEM)**  
    - Most powerful account  
    - More powerful than local admins  
    - Starts Windows services  
  - **Local Service (NT AUTHORITY\LocalService)**  
    - Limited privileges (like local user)  
    - Starts select services  
  - **Network Service (NT AUTHORITY\NetworkService)**  
    - Similar to domain user account  
    - Limited local rights + can auth on network  

---

### Key notes
- Non-interactive accounts: no password  
- Common for service execution + system processes  

---

## Interacting with the Windows Operating System

### Graphical User Interface (GUI)
- Introduced late 1970s (Xerox PARC) → adopted by Apple + Microsoft
- Solves usability issues for non-technical users (no need to memorize commands)
- Allows point-and-click interaction with OS/apps
- Common use cases for sysadmins:
  - Active Directory management
  - IIS configuration
  - Database interaction  

---

### Remote Desktop Protocol (RDP)
- Microsoft proprietary protocol for remote GUI access
- Client ↔ server architecture
- Uses **TCP port 3389**
- Behaves as if user is logged in locally
- Commonly used for:
  - Administering remote systems
  - Remote work after VPN connection  

---

### Windows Command Line

#### Benefits
- Greater control over system
- Supports automation (e.g. bulk user creation)
- Useful for admin + troubleshooting tasks  

#### Interfaces
- **Command Prompt (CMD / cmd.exe)**  
  - Execute commands + scripts
  - Examples:
    - `ipconfig` → view IP info
    - setup scheduled tasks
    - create scripts / batch files  
  - Can open:
    - Start Menu → `cmd`
    - Run dialog → `cmd`
    - `C:\Windows\System32\cmd.exe`

- **PowerShell**
  - (Not covered in this batch but key alternative to CMD)

*Recommended:* Check out the [Windows Command Reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands) for full syntax + examples.

## PowerShell

### Overview
- Command shell + scripting environment designed for system admins  
- Built on **.NET Framework**
- Powerful interface to OS  
- Provides direct access to file system (similar to CMD)

---

### Cmdlets
- Small, single-function tools built-in to PowerShell  
- Form: **Verb-Noun**
- 100+ core cmdlets; can write custom ones  
- Used for:
  - System admin tasks
  - Automation
  - Complex scripting  

Examples:
-> powershell
Get-ChildItem           // List current directory
Get-ChildItem -Recurse  // List current dir + all subdirs
Get-ChildItem -Path C:\Users\Administrator\Documents
Get-ChildItem -Path C:\Users\Administrator\Downloads -Recurse

## PowerShell Execution Policy

- **Execution policy** = security feature to control script execution
- Prevents accidental or malicious script runs  

---

### Execution policy types

| Policy | Description |
|---------|-------------|
| **AllSigned** | All scripts (local + remote) must be signed by trusted publisher; prompt for unlisted publishers |
| **Bypass** | No scripts blocked, no warnings/prompts |
| **Default** | Restricted (desktop) / RemoteSigned (server) |
| **RemoteSigned** | Local scripts: no signature needed; downloaded scripts: require digital signature |
| **Restricted** | No script files run; individual commands allowed |
| **Undefined** | No policy set → defaults apply (Restricted if all scopes = undefined) |
| **Unrestricted** | Unsigned scripts can run; warn on scripts not from local intranet zone |

---

### Notes
- Default:
  - **Windows desktop** → Restricted  
  - **Windows server** → RemoteSigned  
  - **Non-Windows systems** → Unrestricted  

Example check: powershell

Get-ExecutionPolicy -List

### Execution Policy Bypass

- Execution policy is **not a true security control**
- Can be bypassed by:
  - Typing script contents directly in PowerShell
  - Downloading + invoking script manually
  - Using encoded command
  - Adjusting execution policy (if rights permit)
  - Setting policy for current process (no config change; applies for session duration)

Example: set execution policy for current session
```powershell
Set-ExecutionPolicy -Scope Process Bypass

---

## Windows Management Instrumentation (WMI)

WMI = Subsystem in PowerShell for **system monitoring & management**  
Pre-installed since Windows 2000  

---

### Key Components

| Component | Description |
|----------|-------------|
| **WMI service** | Runs at boot; acts as intermediary between providers, repository, and apps |
| **Managed objects** | Logical/physical components WMI can manage |
| **WMI providers** | Monitor events/data of specific objects |
| **Classes** | Pass data to WMI service; used by providers |
| **Methods** | Actions attached to classes (e.g., start/stop remote processes) |
| **WMI repository** | DB storing static WMI-related data |
| **CIM Object Manager** | Requests data from providers and returns to the app |
| **WMI API** | Allows apps to access WMI |
| **WMI Consumer** | Sends queries to objects via CIM Manager |

---

### Common WMI Uses

- Monitor system status (local/remote)
- Configure security settings
- Set/change user & group permissions
- Modify system properties
- Code execution
- Schedule processes
- Setup logging

---

### Using WMI

- WMI via **PowerShell**
- WMI via **WMIC CLI (deprecated but still useful)**

```cmd
# Start WMI interactive shell
wmic

# Run WMI command directly
wmic computersystem get name

In a way, its like linux's SUDO, from what I can tell

---

### Microsoft Management Console (MMC)

The **MMC** is a framework for grouping **snap-ins** (admin tools) used to manage:

- Hardware  
- Software  
- Network components  

**Available on**: All Windows versions since **Windows Server 2000**

---

### Key Features

- Allows the creation of **custom admin consoles**
- Can manage **local and remote** systems
- Snap-ins are modular and can be added based on the admin's needs
- Custom consoles can be **saved & distributed** to other users

---

### What Are Snap-ins?

Snap-ins are the actual admin tools (e.g., Device Manager, Services, Event Viewer).  
You use MMC to **group only what you need** into a single custom UI.

---

### How to Open

```cmd
# Run from Start or Run dialog
mmc

---

## Windows Subsystem for Linux (WSL)

Το **WSL** είναι feature των Windows 10 και Windows Server 2019 που επιτρέπει την εκτέλεση **Linux binaries** natively μέσα από το Windows OS.

Αρχικά φτιάχτηκε για devs που ήθελαν να τρέχουν **Bash, Ruby** και άλλα native Linux CLI tools (`sed`, `awk`, `grep`, κ.λπ.) κατευθείαν μέσα από το Windows workstation.

---

### WSL 2

Η δεύτερη έκδοση (κυκλοφόρησε Μάιο 2019) εισήγαγε **πραγματικό Linux kernel** μέσω Hyper-V components.

---

### Instalation

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux

---

## What is Hyper-V

**Hyper-V** is Microsoft’s virtualization platform (hypervisor) that allows users to create and manage virtual machines (VMs) on Windows systems.

### Definition

Hyper-V is a **Type 1 hypervisor**, meaning it runs directly on the hardware. However, on Windows 10/11, it's implemented within the OS but still behaves like a bare-metal hypervisor. It's built into:

- Windows 10 Pro, Enterprise, and Education
- Windows 11 Pro+
- Windows Server editions

---

### What Can Hyper-V Do?

- Create and manage **Virtual Machines (VMs)**
- Run multiple operating systems (Windows, Linux, etc.) on the same physical host
- Take **snapshots** and restore previous VM states
- Isolated networking and sandboxed environments for testing or malware analysis

---

### Use in WSL 2

**WSL 2** (Windows Subsystem for Linux v2) uses **Hyper-V technology** to run a **real Linux kernel** inside a lightweight VM — though it feels fully integrated with the host Windows OS.

---

### Enabling Hyper-V

To enable Hyper-V, open a PowerShell terminal as Administrator and run:

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All


## Desktop Experience vs. Server Core

**Windows Server Core** was first introduced in **Windows Server 2008** as a minimalistic environment that includes only the essential server components.

### Key Differences

| Feature                         | Server Core                                 | Desktop Experience (GUI) |
|---------------------------------|---------------------------------------------|--------------------------|
| **GUI**                         | Not available                               | Full graphical interface |
| **Management Method**           | Command-Line, PowerShell, Remote (MMC/RSAT) | GUI & CLI                | 
| **Resource Usage**              | Lower (disk, memory, CPU)                   | Higher                   |
| **Attack Surface**              | Smaller                                     | Larger                   |
| **Learning Curve**              | Steep                                       | Easier                   |
| **Use Cases**                   | Headless servers, secure setups             | General-purpose servers  |

### GUI Tools Still Available in Server Core

Even though Server Core has no GUI, some graphical programs are still supported:

- **Registry Editor**
- **Notepad**
- **System Information**
- **Windows Installer**
- **Task Manager**
- **PowerShell**
- **Sysinternals tools** (e.g., `ProcMon`, `ProcExp`, `AD Explorer`, `TCPView`)

### ⚙️ Setup with `Sconfig`

- Server Core setup is done via `Sconfig`, a **text-based VBScript interface**
- Common tasks supported:
  - Network configuration
  - Windows Updates
  - User management
  - Remote management
  - Windows activation

### Applications Not Supported on Server Core

Some apps **cannot run** on Server Core, such as:

- Microsoft SCVMM 2019
- System Center DPM 2019
- SharePoint Server 2019
- Project Server 2019

### Summary

- **Server Core** is a **lightweight, secure** alternative ideal for headless or production environments
- **Desktop Experience** is more flexible and user-friendly, but heavier
- Choose based on:
  - Business needs
  - Application compatibility
  - Admin skill level

---

### Feature Comparison Table

| Application                    | Server Core | Desktop Experience |
|-------------------------------|-------------|--------------------|
| `cmd.exe` (Command Prompt)    | ✅          | ✅                 |
| PowerShell / .NET             | ✅          | ✅                 |
| `regedit`                     | ✅          | ✅                 |
| `diskmgmt.msc`                | ❌          | ✅                 |
| Server Manager                | ❌          | ✅                 |
| `mmc.exe`                     | ❌          | ✅                 |
| `eventvwr`                    | ❌          | ✅                 |
| `services.msc`                | ❌          | ✅                 |
| Control Panel                 | ❌          | ✅                 |
| Windows Explorer              | ❌          | ✅                 |
| Task Manager (`taskmgr`)      | ✅          | ✅                 |
| Internet Explorer / Edge      | ❌          | ✅                 |
| Remote Desktop Services       | ✅          | ✅                 |

---

# Windows Security

Security is a critical topic in Windows operating systems. Windows systems have many moving parts that present a vast attack surface. Due to the many built-in applications, features, and layers of settings, Windows systems can be easily misconfigured — thus opening them up to attack, even if they are fully patched.

It includes many built-in features that can be abused and has suffered from a wide variety of critical vulnerabilities, resulting in widely used and very effective remote and local exploits.

Microsoft has improved upon Windows security over the years. As our world's interconnectedness continues to expand and attackers become more sophisticated, Microsoft has continued to add new features that can be used by systems administrators to:

- Harden systems
- Actively block intrusion attempts
- Detect misuse or exploitation

## Security Principles

Windows follows certain security principles to control **access** and **authentication** within the system. These principles apply to various entities, such as:

- Users
- Networked computers
- Threads
- Processes

These entities can be authorized for specific actions. The Windows security model is designed to:

- Minimize the risk of unauthorized access
- Make it more difficult for attackers or malicious software to exploit the system

---

## Security Identifier (SID)

Each security principal on a Windows system has a unique **Security Identifier (SID)**. These are automatically generated by the system. Even if two users have the same username, their SIDs will differ, allowing Windows to distinguish between them and manage access rights accurately.

SIDs are stored in the **security database** and are included in a user’s **access token**, which is used to determine what actions the user is authorized to perform.

A SID is composed of:

- **Identifier Authority**
- **Relative ID (RID)**

In **Active Directory (AD)** environments, the SID also includes the **domain SID**.

### Example

```powershell
PS C:\htb> whoami /user

USER INFORMATION
----------------
User Name           SID
=================== =============================================
ws01\bob            S-1-5-21-674899381-4069889467-2080702030-1002

### SID Structure

The general format of a SID looks like this:


| Segment                              | Description                                                                 |
|--------------------------------------|-----------------------------------------------------------------------------|
| `S`                                  | Indicates the string is a SID.                                              |
| `1`                                  | Revision Level — always `1` (so far).                                       |
| `5`                                  | Identifier Authority — identifies the system or network that issued the SID.|
| `21`                                 | Subauthority 1 — describes the user's relation/group to the issuing authority.|
| `674899381-4069889467-2080702030`    | Subauthority 2 — identifies the domain or computer that created the SID.    |
| `1002`                               | Relative Identifier (RID) — distinguishes the account (user, admin, guest). |

---

### Security Accounts Manager (SAM) and Access Control Entries (ACE)

The **Security Accounts Manager (SAM)** is responsible for granting rights to execute specific processes across the network.

Access rights are managed using **Access Control Entries (ACEs)**, which are stored in **Access Control Lists (ACLs)**. Each ACL contains ACEs that define which users, groups, or processes have access to securable objects, such as files or services.

Permissions are granted via **security descriptors**, which include two types of ACLs:

- **DACL (Discretionary Access Control List):** Controls access to an object.
- **SACL (System Access Control List):** Used for auditing and logging access attempts.

Every thread or process initiated by a user must go through an **authorization process**. A key component of this process is the **access token**, which is validated by the **Local Security Authority (LSA)**.

These access tokens include:

- The user's **SID**
- A list of group memberships
- User privileges
- And other security-relevant metadata

Understanding these mechanisms is essential during **privilege escalation**, as they govern what actions a user or process is authorized to perform.

---

### User Account Control (UAC)

**User Account Control (UAC)** is a security feature in Windows designed to prevent unauthorized changes to the operating system. It helps block malware from running or altering critical system components.

#### Admin Approval Mode

UAC includes an **Admin Approval Mode**, which prompts users for permission or administrator credentials before allowing potentially harmful changes. You've likely encountered this as a popup when trying to install new software or change system settings.

- If you're logged in as a **standard user**, UAC will prompt for the **administrator password**.
- If you're logged in as an **administrator**, you'll see a **confirmation dialog** instead.

This ensures that:
- Software cannot silently install or modify the system.
- Scripts or binaries (malicious or not) **cannot execute with elevated privileges** without user confirmation.

#### Why It Matters

The **consent prompt** acts as a last line of defense. It interrupts automated execution of potentially harmful code, giving users the opportunity to block the action.

Understanding how UAC operates — its structure and triggers — is key when analyzing privilege escalation opportunities or building hardened Windows environments.

## Registry

The Windows Registry is a **hierarchical database** that stores low-level settings for the operating system and for applications that opt to use it. It contains both **computer-specific** and **user-specific** data.

You can open the Registry Editor by typing `regedit` from the command line or Windows search bar.

---

### Structure

The Registry has a **tree-like structure** consisting of:
- **Root keys (main folders)**: Start with `HKEY`
- **Subkeys (subfolders)**: Nested under root keys
- **Values**: Entries inside each subkey

---

### Root Keys

| Root Key | Abbreviation | Description |
|----------|--------------|-------------|
| HKEY_LOCAL_MACHINE | `HKLM` | Stores settings relevant to the **local system** |
| HKEY_CURRENT_USER | `HKCU` | User-specific configuration for the **currently logged-in user** |
| HKEY_CLASSES_ROOT | `HKCR` | File associations and object linking |
| HKEY_USERS | `HKU` | Settings for all users on the machine |
| HKEY_CURRENT_CONFIG | `HKCC` | Hardware profile information used at boot |

> `HKLM` includes subkeys like: `SAM`, `SECURITY`, `SYSTEM`, `SOFTWARE`, `HARDWARE`, and `BCD`.  
> All loaded at boot **except** `HARDWARE`, which is dynamically loaded.

---

### Registry Value Types

There are **11 main value types** that can be assigned inside a subkey:

| Value Type | Description |
|------------|-------------|
| `REG_BINARY` | Binary data in any form |
| `REG_DWORD` | 32-bit number |
| `REG_DWORD_LITTLE_ENDIAN` | 32-bit number (default format on Windows) |
| `REG_DWORD_BIG_ENDIAN` | 32-bit number (big-endian, used in some UNIX systems) |
| `REG_EXPAND_SZ` | String with expandable environment vars (e.g. `%PATH%`) |
| `REG_LINK` | Symbolic link path (Unicode string) |
| `REG_MULTI_SZ` | Multiple null-terminated strings (e.g. `Str1\0Str2\0Str3\0\0`) |
| `REG_NONE` | No defined type |
| `REG_QWORD` | 64-bit number |
| `REG_QWORD_LITTLE_ENDIAN` | 64-bit number in little-endian format |
| `REG_SZ` | Simple null-terminated string (Unicode or ANSI) |

> Source: [Microsoft Docs – Registry Value Types](https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types)

---

### Example: Registry Editor UI

- Path: `HKEY_LOCAL_MACHINE`
- Key: `Analysis`
- Value: `DWORD` set to `0`

---
## Application Whitelisting

**Application Whitelisting** is a security approach that involves creating a list of **approved software or executables** that are allowed to run on a system. Its primary purpose is to **prevent unauthorized, unknown, or malicious software** from being executed.

### Key Concepts

- **Whitelisting** = Only **approved applications** are allowed. All else is blocked.
- **Blacklisting** = Only **known malicious or unwanted apps** are blocked. Everything else is allowed.
- **Zero Trust Principle**: Everything is denied by default unless explicitly allowed.
- **Audit Mode**: A recommended first step to ensure legitimate applications aren't blocked by mistake.

> ⚠️ Implementing whitelisting in large environments can be challenging.  
> It should begin in **audit mode** to prevent business disruption.

---

### Benefits of Whitelisting

- Better control over software execution
- Reduces risk from unknown malware
- Less overhead for maintaining block lists (vs. blacklisting)

> Recommended by security organizations such as **NIST**, especially for high-security systems.

---

## AppLocker

**AppLocker** is Microsoft’s native application whitelisting tool, introduced in **Windows 7**.

### Features

AppLocker allows administrators to define **rules** for:

- **Executables (.exe)**
- **Scripts (.ps1, .bat, .cmd, .vbs, .js)**
- **Windows Installer files (.msi, .msp)**
- **DLLs**
- **Packaged apps** and **packaged app installers**

### Rule Types

Rules can be based on:

- **Publisher name** (from digital signature)
- **Product name**
- **File name**
- **Version**
- **File path**
- **Hash**

Rules can be applied to:

- Specific **users**
- **Security groups**

> AppLocker also supports **audit mode**, to test enforcement before applying full restrictions.

---

## Local Group Policy

**Group Policy** is a feature in Windows that allows administrators to configure and enforce settings across users and systems.

### Domain vs Local Group Policy

- In **domain environments**, **Group Policy Objects (GPOs)** are configured on a **Domain Controller (DC)** and applied to **domain-joined machines**.
- In **non-domain environments**, or for local settings on a single machine, we use **Local Group Policy**.

---

### What Can Be Configured?

Local Group Policy can be used to control:

- System behavior
- User permissions
- Installed applications
- Password and authentication policies
- Network configurations
- Graphical interface restrictions

> It's especially useful for **locking down standalone systems** with strict security requirements.

---

# Windows Defender Antivirus

Windows Defender Antivirus (Defender), formerly known as Windows Defender, is the built-in antivirus software that ships for free with Windows operating systems.

## History

- Initially released as a **downloadable anti-spyware tool** for Windows XP and Server 2003.
- Bundled natively starting from **Windows Vista / Server 2008**.
- Renamed to **Windows Defender Antivirus** with **Windows 10 Creators Update**.

## Key Features

- **Real-time Protection**  
  Monitors and protects against known threats in real time.

- **Cloud-delivered Protection**  
  Works alongside automatic sample submission to send suspicious files to Microsoft’s cloud for analysis.  
  Files are “locked” during analysis to prevent damage.

- **Tamper Protection**  
  Prevents changes to Defender security settings via:
  - Registry
  - PowerShell
  - Group Policy

- **Controlled Folder Access**  
  Defender's **Ransomware protection** feature.  
  Prevents unauthorized changes to specified folders.

## Configuration & Management

- Managed via **Windows Security Center**.
- From the Security Dashboard, users can:
  - Monitor virus protection status
  - Enable/disable real-time protection
  - Add exclusions (files/folders) from scans
  - Modify Controlled Folder Access settings

> Tip: Penetration testers often **exclude tools** from Defender scans to prevent them from being flagged and quarantined.

## UI Example

Windows Security dashboard shows:
- Virus protection: ❌ Off  
- Account protection: ✅ OK  
- Firewall: ❌ Off



