## Accessing Windows

## Table of Contents
- [Introduction to Windows](#introduction-to-windows)
- [The Windows Operating System](#the-windows-operating-system)
- [Windows Versions](#windows-versions)
- [Accessing Windows](#accessing-windows)
  - [Local Access](#local-access)
  - [Remote Access](#remote-access)
    - [Remote Desktop Protocol (RDP)](#remote-desktop-protocol-rdp)
    - [Remote Desktop Connection (RDC)](#remote-desktop-connection-rdc)
    - [Using xfreerdp](#using-xfreerdp)
- [Operating System Structure](#operating-system-structure)

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

👉 Think of it as:
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
✅ Pros:
- Great device compatibility (computers, cameras, consoles, smartphones, tablets)  
- OS cross-compatibility (Windows 95+, macOS, Linux)

❌ Cons:
- Max file size: **<4GB**
- No built-in data protection / compression
- No native encryption (needs 3rd-party tools)

---

### NTFS
Default since **Windows NT 3.1**  
✅ Pros:
- Reliable (can restore FS consistency after failure)
- Supports granular permissions
- Very large partition support
- Journaling (logs file changes)

❌ Cons:
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

ℹ️ By default:
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

💡 Someone accessing locally (e.g. console, RDP) only deals with **NTFS perms**.  
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
✅ List shares:
-> bash
smbclient -L <target_IP> -U htb-student

smbclient '\\<target_IP>\Company Data' -U htb-student

