# 📚 Table of Contents
- [📚 Table of Contents](#-table-of-contents)
- [Introduction - What Is macOS?](#introduction---what-is-macos)
  - [🕰️ History Timeline](#️-history-timeline)
  - [🧠 Architecture Overview](#-architecture-overview)
    - [Apple Silicon](#apple-silicon)
  - [🧩 Core Components](#-core-components)
  - [Summary](#summary)
  - [macOS Graphical User Interface (GUI)](#macos-graphical-user-interface-gui)
- [Graphical User Interface](#graphical-user-interface)
  - [🧱 Main GUI Components](#-main-gui-components)
  - [🖱️ Apple Menu](#️-apple-menu)
  - [🗂️ Finder](#️-finder)
  - [🔍 Spotlight](#-spotlight)
  - [🚀 Dock](#-dock)
  - [📦 Launchpad](#-launchpad)
  - [🎛️ Control Center](#️-control-center)
  - [Summary](#summary-1)
- [Navigating Around the macOS](#navigating-around-the-macos)
  - [📁 Finder Essentials](#-finder-essentials)
    - [Viewing the Root Directory](#viewing-the-root-directory)
    - [Copy, Paste, and Move](#copy-paste-and-move)
    - [Terminal Move Example](#terminal-move-example)
  - [👻 Viewing Hidden Files](#-viewing-hidden-files)
    - [Using GUI](#using-gui)
    - [Using Terminal](#using-terminal)
  - [🖼️ Preview Pane](#️-preview-pane)
  - [🔍 Spotlight Search](#-spotlight-search)
  - [🪟 App Navigation](#-app-navigation)
    - [Mission Control](#mission-control)
    - [Split View](#split-view)
  - [Summary](#summary-2)
- [System Hierarchy](#system-hierarchy)
  - [📂 macOS Domains](#-macos-domains)
  - [🗃️ Standard Directories](#️-standard-directories)
    - [`/Applications`](#applications)
    - [`/Users`](#users)
    - [`/Library`](#library)
    - [`/Network`](#network)
    - [`/System`](#system)
  - [🧱 Unix-Specific Directories](#-unix-specific-directories)
  - [🔎 Tips](#-tips)
  - [Summary](#summary-3)
- [File and Directory Permissions](#file-and-directory-permissions)
  - [🧮 \*NIX Permissions Primer](#-nix-permissions-primer)
    - [Permission Types and Octal Values](#permission-types-and-octal-values)
    - [Directories and Execute](#directories-and-execute)
  - [🧰 GUI Permissions Management](#-gui-permissions-management)
    - [How to View \& Modify:](#how-to-view--modify)
  - [💻 Terminal Permissions Management](#-terminal-permissions-management)
    - [`chmod`: Change Permissions](#chmod-change-permissions)
  - [🔐 Security Implications](#-security-implications)
  - [Summary](#summary-4)
- [Networking](#networking)
  - [🌐 Viewing Network Info (GUI)](#-viewing-network-info-gui)
    - [✅ System Information](#-system-information)
    - [✅ System Settings](#-system-settings)
    - [✅ Control Center](#-control-center)
  - [🖥️ CLI Networking Commands](#️-cli-networking-commands)
    - [ifconfig](#ifconfig)
    - [lsof](#lsof)
    - [networksetup](#networksetup)
  - [⚙️ Tips \& Tricks](#️-tips--tricks)
    - [networkQuality](#networkquality)
    - [View Saved Wi-Fi Password](#view-saved-wi-fi-password)
  - [🔐 VPN Options](#-vpn-options)
    - [Tunnelblick](#tunnelblick)
    - [Viscosity](#viscosity)
  - [📡 Bonjour (ZeroConf)](#-bonjour-zeroconf)
  - [Summary](#summary-5)
- [Application Management](#application-management)
  - [🛍️ App Store](#️-app-store)
  - [🌐 Third-Party Applications](#-third-party-applications)
  - [🍺 Homebrew (Package Manager)](#-homebrew-package-manager)
    - [Install Homebrew:](#install-homebrew)
    - [Check installation:](#check-installation)
  - [📦 Installing Tools with Homebrew](#-installing-tools-with-homebrew)
    - [Example Output:](#example-output)
  - [🖥️ Homebrew Cask](#️-homebrew-cask)
  - [🧪 macOS for Pentesting](#-macos-for-pentesting)
    - [Recommended:](#recommended)
    - [Safe-to-install native tools:](#safe-to-install-native-tools)
  - [Summary](#summary-6)
- [Security Tips](#security-tips)
  - [🔐 Application Security Considerations](#-application-security-considerations)
    - [App Store](#app-store)
    - [Identified Developers](#identified-developers)
    - [Unidentified Developers](#unidentified-developers)
    - [Package Managers](#package-managers)
  - [🔁 Auto Updates](#-auto-updates)
    - [macOS Updates](#macos-updates)
    - [Third-party Apps](#third-party-apps)
  - [🛡️ Built-in macOS Security](#️-built-in-macos-security)
    - [Application Privacy](#application-privacy)
    - [FileVault](#filevault)
    - [Firewall](#firewall)
    - [Keychain](#keychain)
    - [Find My Mac](#find-my-mac)
    - [iCloud Private Relay](#icloud-private-relay)
    - [Hide My Email](#hide-my-email)
    - [Advanced Data Protection](#advanced-data-protection)
    - [Lockdown Mode](#lockdown-mode)
  - [🛠️ Recommended Security Tools](#️-recommended-security-tools)
    - [Objective-See Tools (https://objective-see.org)](#objective-see-tools-httpsobjective-seeorg)
  - [Summary](#summary-7)
  - [MacOS Terminal](#macos-terminal)
    - [macOS vs. Linux Terminals](#macos-vs-linux-terminals)
  - [ZSH Overview](#zsh-overview)
- [macOS Productivity Tips](#macos-productivity-tips)
  - [Device Switching (Continuity Features)](#device-switching-continuity-features)
  - [Time Management](#time-management)
  - [Reminders](#reminders)
  - [Note-Taking](#note-taking)
  - [Cloud Storage](#cloud-storage)
  - [Multitasking](#multitasking)
  - [Summary](#summary-8)



# Introduction - What Is macOS?

macOS is the official operating system for Apple computers, known for its sleek UI and strong integration across Apple devices. It is second in market share to Windows and is widely used in homes, businesses, and the creative industry.

---

## 🕰️ History Timeline

| Year(s)      | Version & Codename                         | Key Highlights                                                   |
|--------------|--------------------------------------------|------------------------------------------------------------------|
| 2000–2002    | Mac OS X 10.0–10.2 (Cheetah, Puma, Jaguar) | Introduced Aqua UI, replaced OS 9, launched iChat                |
| 2003         | 10.3 (Panther)                             | Safari replaced IE, Active Directory support                     |
| 2005         | 10.4 (Tiger)                               | Intel chipset support introduced                                 |
| 2007–2009    | 10.5–10.6 (Leopard, Snow Leopard)          | Time Machine, 64-bit apps, Boot Camp, App Store, dropped PowerPC |
| 2011–2012    | 10.7–10.8 (Lion, Mountain Lion)            | iCloud integration, iOS-like gestures, iOS features ported to Mac|
| 2013         | 10.9 (Mavericks)                           | New naming scheme (California landmarks), free upgrades          |
| 2014–2015    | 10.10–10.11 (Yosemite, El Capitan)         | Handoff, iOS-like UI, Split View multitasking                    |
| 2016–2017    | 10.12–10.13 (Sierra, High Sierra)          | Rebranded to "macOS", Siri, Apple Pay, switched to APFS          |
| 2018         | 10.14 (Mojave)                             | Dark Mode, dynamic themes, more iOS apps ported                  |
| 2019         | 10.15 (Catalina)                           | Split iTunes into TV/Podcasts/Music, Sidecar support             |
| 2020         | 11 (Big Sur)                               | New UI, Apple Silicon support begins                             |
| 2021         | 12 (Monterey)                              | Universal Control, AirPlay updates, SharePlay                    |
| 2022         | 13 (Ventura)                               | Stage Manager, Continuity Camera, redesigned Settings app        |

---

## 🧠 Architecture Overview

- **Kernel:** XNU (based on Mach & BSD)
- **OS Base:** Darwin (FreeBSD derivative, open-source)

### Apple Silicon
Recent versions of macOS now focus on Apple Silicon processors (ARM), though Intel support continues temporarily.

---

## 🧩 Core Components

| Component             | Description                                                                 |
|-----------------------|-----------------------------------------------------------------------------|
| **Aqua**              | The main GUI theme of macOS with flowy animations and transparency          |
| **Finder**            | The file manager and desktop environment component                          |
| **Sandboxing**        | Application isolation to limit access and enhance security                  |
| **Cocoa**             | App layer/API for macOS apps and native Apple functionality (Siri, etc.)    |

---

## Summary

macOS is a Unix-based OS derived from Darwin and FreeBSD, utilizing a hybrid XNU kernel. Its development has transitioned from big cats to California landmarks, from PowerPC to Intel and now to Apple Silicon. Its GUI is defined by Aqua, its file management by Finder, and its app logic by Cocoa, all wrapped in a secure sandboxed environment.

---

## macOS Graphical User Interface (GUI)

macOS features a refined and powerful Graphical User Interface (GUI), designed for productivity and accessibility. Below are the core components that define the macOS GUI and enhance user interaction.

---
# Graphical User Interface

## 🧱 Main GUI Components

| Component       | Description                                                                 |
|-----------------|-----------------------------------------------------------------------------|
| **Apple Menu**  | Central access point for system settings, shutdown/restart, and lock screen |
| **Finder**      | File management and desktop experience                                       |
| **Spotlight**   | Search tool for local and cloud content, performs quick math and queries     |
| **Dock**        | Application launcher and quick access bar for open or favorite apps          |
| **Launchpad**   | Visual application menu, searchable and scrollable                           |
| **Control Center** | Quick settings panel for network, display, sound, and other toggles       |

---

## 🖱️ Apple Menu

Located in the top-left corner of the screen. It provides:
- Access to **System Settings**, **App Store**, and **About This Mac**
- Fast actions like **Sleep**, **Restart**, **Shut Down**, and **Lock Screen**
- Viewing system specs and storage via *More Info* under *About This Mac*

---

## 🗂️ Finder

Finder is the macOS file manager and desktop environment:
- Displays **desktop items**, **sidebar navigation**, and **menu bar**
- Manages files, folders, mounted drives, and system locations
- Can launch other apps and interact with the GUI elements

---

## 🔍 Spotlight

Spotlight offers powerful search functionality:
- Searches local files, iCloud, apps, emails, media, etc.
- Performs **unit conversions**, **calculations**, and **news lookups**
- Accessed via **magnifying glass icon** in top-right corner or keyboard shortcut
- Integrated with Siri for extended search features

---

## 🚀 Dock

A customizable taskbar typically found at the bottom of the screen:
- Holds **frequently used** and **currently running apps**
- Offers quick access to **Finder**, **Trash**, **System Settings**, etc.
- Position can be changed to left/right of the screen

---

## 📦 Launchpad

Acts as a full-screen application menu:
- Displays all installed apps from the `/Applications` folder
- Can be accessed via:
  - Five-finger pinch on trackpad
  - Spotlight search
  - Dock shortcut
- Supports quick type-to-search filtering

💡 *Trackpad Gestures* can be viewed and configured in:  
`System Settings` → `Trackpad`

---

## 🎛️ Control Center

Quick-access panel for commonly used settings:
- Manage **Wi-Fi**, **Bluetooth**, **AirDrop**, **Focus**, **Display**, **Sound**, etc.
- Offers **customization** for frequently used settings
- Accessible from the top-right corner icon next to system status

---

## Summary

macOS provides a clean, consistent, and customizable GUI environment designed for intuitive interaction and multitasking. Mastering these components — from Spotlight searches to Dock efficiency — is key for seamless operation across Apple’s ecosystem.

---

# Navigating Around the macOS

macOS offers several efficient methods for navigating files, folders, and apps. Understanding Finder, keyboard shortcuts, and workspace tools is key for streamlined workflows.

---

## 📁 Finder Essentials

### Viewing the Root Directory
- **Method 1**: Finder → Go → Computer → Storage  
- **Method 2**: `Command + Shift + G` → type `/` → Go  
- **Navigation**: Use `Command + ↑` and `Command + ↓` to move up/down directories

### Copy, Paste, and Move
- **Copy**: `Command + C`  
- **Paste**: `Command + V`  
- **Move**: `Command + Option + V` (no GUI cut-paste option)  
- **Duplicate via Drag**: Hold `Option` while dragging a file

### Terminal Move Example
`mv /Users/htb-student/Documents/Test /Users/htb-student/Desktop/Test`  
⚠️ `mv` is irreversible — use with caution

---

## 👻 Viewing Hidden Files

### Using GUI
- Open a folder
- Press `Command + Shift + .` to toggle hidden files

### Using Terminal
- `defaults write com.apple.Finder AppleShowAllFiles true`  
- `killall Finder`

---

## 🖼️ Preview Pane

- Access via Finder → View → Show Preview  
- Displays image/content preview and file metadata:  
  - Created Date  
  - Modified Date  
  - Last Opened

---

## 🔍 Spotlight Search

- Open with `Command + Space` or click the magnifying glass (top right)
- Supports:
  - File/app search
  - Calculations & unit conversion
  - Web/iCloud lookup
- Example: Type `dictionary` and open the Dictionary app

---

## 🪟 App Navigation

### Mission Control
- Opens a bird’s-eye view of all desktops and windows
- Open via:
  - Three-finger swipe up on trackpad
  - Launchpad → Mission Control

### Split View
- Hover over **green full-screen** button
- Select:
  - Tile Window to Left of Screen
  - Tile Window to Right of Screen
- Then choose another app to split the screen

---

## Summary

By mastering Finder, Spotlight, and macOS multitasking tools like Mission Control and Split View, users can navigate the system quickly and effectively. Hidden files, quick previews, and efficient window management are built-in for power users and pros alike.

---

# System Hierarchy

macOS uses a hybrid file system structure that combines Unix-style hierarchy with Apple’s domain-based model. Understanding this layout is essential for locating apps, configs, user data, and system-level resources.

---

## 📂 macOS Domains

macOS separates files into distinct domains for access control and logical organization:

| Domain         | Description                                                                 |
|----------------|-----------------------------------------------------------------------------|
| **User Domain**   | User-specific apps and data, e.g. `/Users/username`                        |
| **Local Domain**  | Shared apps and resources across all users, e.g. `/Applications`            |
| **System Domain** | macOS core files and Apple-installed apps, e.g. `/System/Library`           |
| **Network Domain**| Network-shared resources and documents (if present), e.g. `/Network`        |

---

## 🗃️ Standard Directories

### `/Applications`
Holds installed applications, varying by domain:
- **User**: `/Users/username/Applications`
- **Local**: `/Applications`
- **System**: `/System/Applications`

### `/Users`
Stores individual user directories:
- Each user has a folder: `/Users/htb-student`, `/Users/htb-dev`, etc.
- Users can only access their own home directories

### `/Library`
Stores app data, preferences, and shared resources:
- **User**: `/Users/username/Library`
- **Local**: `/Library`
- **System**: `/System/Library`

Key Subfolders:
- `Application Support`: App-specific config/data files
- `Caches`: Temporary app files
- `Frameworks`: Shared libraries for apps
- `Preferences`: App/system settings (e.g. Logging, SoftwareUpdate)

### `/Network`
Lists LAN-accessible systems and networked shares (when available)

### `/System`
Contains immutable system files required by macOS  
🛑 Do not modify — managed entirely by Apple

---

## 🧱 Unix-Specific Directories

Although Apple uses its own FS layout, it retains traditional Unix paths:

| Directory    | Description                                                                 |
|--------------|-----------------------------------------------------------------------------|
| `/`          | Root filesystem — entry point of everything                                 |
| `/bin`       | Core binaries (e.g. `ls`, `cp`)                                              |
| `/dev`       | Device files used to interface with hardware                                |
| `/etc`       | System and app config files                                                 |
| `/sbin`      | Admin binaries (e.g. `ifconfig`, `fsck`)                                     |
| `/tmp`       | Temporary runtime files — wiped on reboot                                   |
| `/usr`       | Userland software, libs, apps (e.g. `vim`, `ssh`)                            |
| `/var`       | Log files, mail, DBs, web server content                                    |
| `/private`   | Underlying system files (e.g. real locations for `/tmp`, `/var`, `/etc`)    |
| `/opt`       | Third-party software installed outside of App Store                         |
| `/cores`     | Core dumps generated during app/system crashes                              |
| `/home`      | User home directories (may be symlinked to `/Users`)                        |

---

## 🔎 Tips

- Many macOS folders are **protected or hidden** to prevent tampering
- Use `man hier` for more info on standard Unix directory layout
- macOS tools like **Finder** or **Spotlight** may abstract this structure

---

## Summary

macOS blends classic Unix structure with Apple-specific domains to organize user data, system files, and applications. Recognizing the differences between `/System`, `/Library`, `/Users`, and `/Applications` is critical for navigating, managing, and securing macOS effectively.

---

# File and Directory Permissions

macOS, being Unix-based, implements standard *nix file permission structures. Understanding and managing these permissions is key to maintaining system security and file integrity.

---

## 🧮 *NIX Permissions Primer

Every file and directory has:
- **User Owner**: the creator/owner of the file
- **Group Owner**: usually the primary group of the user
- **Others**: everyone else on the system

### Permission Types and Octal Values

| Attribute | Symbol | Octal Value |
|-----------|--------|-------------|
| Read      | `r`    | 4           |
| Write     | `w`    | 2           |
| Execute   | `x`    | 1           |

The permission string is split into 3 sets: `UGO` (User, Group, Others). Example:
`rw-r--r--@ 1 htb-user staff 2512910 Aug 30 2019 HTB-Wallpaper-1.png`

- `htb-user` has `rw-` (read/write)
- `staff` group has `r--` (read)
- Others have `r--` (read)
- `@` indicates extended attributes
- `-` means it's a file (`d` for directory)

### Directories and Execute

To **enter or traverse a directory**, the `x` (execute) permission is required.

---

## 🧰 GUI Permissions Management

### How to View & Modify:
1. Right-click file → **Get Info**  
   or press `Command + Option + I`
2. Click the **lock icon** to authenticate
3. Adjust permissions from the dropdown next to each user
4. Use `+` to add users, `–` to remove them

⚠️ GUI changes require admin rights and should be used carefully to avoid overexposing files.

---

## 💻 Terminal Permissions Management

### `chmod`: Change Permissions

Example:
```bash
chmod -vv 777 HTB-Wallpaper-1.png
```

- Sets rwx for User, Group, and Others
- vv shows old/new octal and symbolic permissions
- **chown**: Change Ownership
- Change file owner: sudo chown htb-student HTB-Wallpaper-1.png
- Change owner and group: sudo chown htb-user:admins HTB-Wallpaper-1.png
- chgrp: Change Group Only
- sudo chgrp admins HTB-Wallpaper-1.png

## 🔐 Security Implications

- File permissions are a foundational part of securing a macOS host:
    - Prevent unauthorized modification (Integrity)
    - Limit visibility (Confidentiality)
    - Ensure access where appropriate (Availability)
- Careful permission management helps prevent privilege escalation, data exposure, and accidental deletion.

## Summary

- macOS leverages classic Unix permissions for managing access. Through chmod, chown, and GUI tools, users can control read/write/execute access and ownership across files and directories. Knowing how to interpret and modify these values is essential for secure system administration.

---

# Networking

macOS offers multiple ways to manage and inspect networking: GUI (System Settings & Control Center) and CLI. While GUI management is preferred for persistence, the CLI provides more control and visibility into what’s happening under the hood.

---

## 🌐 Viewing Network Info (GUI)

### ✅ System Information
- Launch from Spotlight: System Information
- Go to **Network** tab to view all hardware interfaces and their status

### ✅ System Settings
- macOS 13+: Go to **System Settings** → **Network**
- Older versions: Use **System Preferences** → **Network**
- Click **Advanced** to view/edit interface config (e.g. IP, subnet, DNS)

> Note: To make persistent changes, prefer GUI. CLI changes may be overwritten on reboot.

### ✅ Control Center
- Click top-right status bar → View/manage **Wi-Fi**, **Bluetooth**, **AirDrop**, etc.
- Click arrow beside item to view detailed controls or open full settings

---

## 🖥️ CLI Networking Commands

### ifconfig
Shows interfaces and network configs.

- View all interfaces:
  ifconfig

- View one interface:
  ifconfig en0

- Set temporary IP:
  sudo ifconfig en0 inet 192.168.1.1 netmask 255.255.255.0

> ⚠️ Not persistent — will be reset on reboot

### lsof
List open ports and sockets:
  lsof -n -i4TCP -P

- Shows bound/established connections
- Remove `-P` to see protocol names instead of port numbers

### networksetup
Apple-specific tool to manage network services.

| Command                                                              | Description                  |
|----------------------------------------------------------------------|------------------------------|
| networksetup -listallnetworkservices                                 | List all network interfaces  |
| networksetup -listnetworkserviceorder                                | Show interface priority      |
| networksetup -getinfo Wi-Fi                                          | View info on Wi-Fi           |
| networksetup -getcurrentlocation                                     | Show active network location |
| networksetup -setmanual Wi-Fi 192.168.1.10 255.255.255.0 192.168.1.1 | Set static IP                |

Use `networksetup -help` for full command list.  
Requires **sudo** to modify settings.

---

## ⚙️ Tips & Tricks

### networkQuality
Check connection speed and responsiveness:
  networkQuality -I en0

- Output: Downlink, Uplink, RPM (Responsiveness per Minute)

### View Saved Wi-Fi Password
  security find-generic-password -wa "<SSID name>"

---

## 🔐 VPN Options

### Tunnelblick
- Free & open-source
- Works with .ovpn configs
- Supports auto-reconnect, persistent configs
- Highly configurable (ideal for HTB/work VPNs)

### Viscosity
- Paid ($14 one-time)
- Clean UI, stats, supports OpenVPN
- Better UX for beginners

> Other vendor-specific VPNs exist, but may not support custom configs (e.g., .ovpn for HTB).

---

## 📡 Bonjour (ZeroConf)

- Apple's **zero-configuration networking** protocol
- Enables discovery of printers, TVs, AirPlay, file shares, etc.
- Powered by: mDNSResponder
- Pros: auto-discovery in LANs (great for IT setup)
- Cons: potential **security risk** if misconfigured (unauthenticated access)

Admins should:
- Use segmentation
- Implement authentication
- Monitor mDNS traffic for suspicious behavior

---

## Summary

macOS networking can be managed via GUI or CLI. Use **System Settings** for persistent configurations and **CLI tools** like ifconfig, lsof, and networksetup for deeper inspection or scripting. VPNs like Tunnelblick and Bonjour support are built-in, but carry both convenience and risk. Understanding these tools is essential for both system administration and penetration testing contexts.

---

# Application Management

macOS supports installing software through the App Store, third-party sources, or command-line tools like Homebrew. While this flexibility enables powerful setups (especially for pentesting), it also increases the risk of unintentionally installing unwanted software.

---

## 🛍️ App Store

- Open the **App Store** app → Search for app → Click **GET** or price
- Installed apps appear in `/Applications`
- To uninstall: drag the app to the **Trash**

---

## 🌐 Third-Party Applications

- Download `.dmg` or `.pkg` files from vendor websites
- Two common install methods:
  - **Drag-and-drop** the app bundle into `/Applications` (e.g. Chrome)
  - Use an **installer wizard** for bundled setups (e.g. Adobe, Office)

> If installed via wizard, an uninstaller is usually provided. Deleting manually may leave behind files.

---

## 🍺 Homebrew (Package Manager)

Homebrew is a powerful CLI tool for managing CLI tools and GUI apps on macOS.

### Install Homebrew:
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

> Reopen Terminal after install to update PATH.

### Check installation:
  brew -v

---

## 📦 Installing Tools with Homebrew

- Install tool (e.g. PHP):
  brew install php

- Uninstall tool:
  brew uninstall php

- Search packages:
  brew search firefox

### Example Output:
firefox
homebrew/cask-versions/firefox-beta
homebrew/cask-versions/firefox-esr

---

## 🖥️ Homebrew Cask

Homebrew includes **Cask** to install GUI applications.

- Install GUI app:
  brew install firefox --cask

> Apps installed via Cask appear in `/Applications`

---

## 🧪 macOS for Pentesting

macOS can serve both as:
1. A **host system** for running pentesting VMs
2. A **native environment** for installing common tools

### Recommended:
- Use a VM (VirtualBox, VMware, Parallels) to isolate pentesting activities
- Download OS ISO (e.g. Kali) and install as VM
- Keep malware/sensitive scripts sandboxed from macOS

### Safe-to-install native tools:
- Nmap
- Burp Suite
- PowerShell
- Ghidra
- VSCode
- SQLMap
- VirtualBox

Many can be installed directly using Homebrew:
  brew install nmap burpsuite powershell ghidra --cask

---

## Summary

macOS supports app installation via the App Store, vendor downloads, and Homebrew. Homebrew enables fast CLI-based installs of pentesting tools. While native support exists for many tools, sandboxing through a VM remains best practice for safe and isolated testing.

---

# Security Tips

macOS offers various mechanisms to keep the system secure. However, since most breaches occur via executables, it is critical to understand how macOS manages app security, built-in protections, and how we can further harden the system.

---

## 🔐 Application Security Considerations

### App Store
- Most secure option
- All apps are signed & verified by Apple
- macOS blocks apps not from the App Store

### Identified Developers
- Trusted vendors (Google, Microsoft, Adobe)
- macOS allows installation of apps signed with valid Apple-issued certificates
- Protected by **Gatekeeper**, **File Quarantine**, and **Code Signing**

### Unidentified Developers
- Blocked by Gatekeeper
- Can be bypassed (not recommended)
- Avoid cracked/patched apps — potential for backdoors & malware

### Package Managers
- Homebrew is unofficial, open-source
- Be cautious; not all packages are reviewed
- Stick to trusted tools (e.g. php, node, jq, etc.)

---

## 🔁 Auto Updates

### macOS Updates
Enable:  
System Settings → General → Software Update → Automatic Updates  
Ensure all toggles (Download, Install, Security updates) are ON

### Third-party Apps
Most have auto-updates enabled by default  
Some may need manual checking within app settings

---

## 🛡️ Built-in macOS Security

### Application Privacy
System Settings → Privacy & Security  
Controls access to:
- Camera / Microphone
- Screen recording
- Files and Folders / Full Disk Access
- Input Monitoring

Sandboxing prevents full system access even if a vulnerable app is exploited

### FileVault
- Full disk encryption
- On by default on Apple Silicon
- Enable: System Settings → Privacy & Security → FileVault

### Firewall
- Enable:  
  - macOS ≤12: System Preferences → Security & Privacy → Firewall  
  - macOS 13+: System Settings → Network → Firewall
- Blocks unauthorized inbound connections
- Supports stealth mode & per-app rules

### Keychain
- Native password manager
- Stores passwords, 2FA tokens, passkeys
- Autofill support across Safari and apps
- Detects weak/reused/compromised credentials

### Find My Mac
- Enable via: System Settings → Apple ID → Find My Mac
- Allows remote **locate**, **lock**, or **erase**
- Works even if the Mac is offline

### iCloud Private Relay
- Apple’s double-hop encrypted proxy
- Hides IP & encrypts DNS + traffic
- May slow speeds or break dev tools (Git, Docker)

### Hide My Email
- Generates disposable email aliases
- For spam protection or anonymous signups
- Enable via: System Settings → Apple ID

### Advanced Data Protection
- Enables end-to-end encryption for all iCloud content
- Protects backups, photos, notes, drive files, etc.
- Disables Apple’s ability to recover your data if password is lost

### Lockdown Mode
- Extreme hardening mode (for high-risk individuals)
- Disables services, limits messaging/browsing, blocks unknown apps
- Enable via: System Settings → Privacy & Security

---

## 🛠️ Recommended Security Tools

### Objective-See Tools (https://objective-see.org)

| Tool         | Function                                                    |
|--------------|-------------------------------------------------------------|
| KnockKnock   | Scan for persistent malware                                 |
| BlockBlock   | Real-time persistent threat monitoring                      |
| Netiquette   | Show & evaluate live network connections                    |
| LuLu         | Outbound firewall — prompt before network connections       |
| TaskExplorer | Analyze running processes for malware behavior              |
| RansomWhere? | Detect & block ransomware encryption attempts               |

> Use **KnockKnock** and **Netiquette** for periodic audits.  
> Use **BlockBlock** and **LuLu** for continuous monitoring (devs may find them noisy).

---

## Summary

macOS is secure-by-default, but extending it with apps introduces risk. Use App Store or trusted developers, enable FileVault, firewall, and auto-updates, and periodically monitor system activity with tools like KnockKnock and Netiquette. Advanced features like Lockdown Mode and Hide My Email help take security to the next level.

---

## MacOS Terminal

macOS is based on the Darwin kernel, a certified UNIX OS, making its terminal experience similar to Linux. Most POSIX commands work across both systems. macOS uses `zsh` by default (since Catalina), while Linux typically uses `bash`.

---

### macOS vs. Linux Terminals

| Feature           | macOS (Darwin)         | Linux                    |
|-------------------|------------------------|--------------------------|
| Shell             | ZSH (default)          | Bash (usually)           |
| Kernel Base       | Darwin (UNIX)          | Linux kernel             |
| POSIX Compliance  | High                   | High                     |
| GUI Integration   | `open` for files/apps  | Usually `xdg-open`       |

POSIX-friendly scripts (`#!/bin/sh`) work across both systems. Many pentesting tools use this style (e.g., `nmapAutomator`, `linPEAS`) for compatibility.

---

## ZSH Overview

ZSH is the default shell in modern macOS. It's extensible, user-friendly, and supports plugins.

---

# macOS Productivity Tips

## Device Switching (Continuity Features)

| Feature                 | Description                                                                                              | Usage Example                                                                                   |
|-------------------------|----------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| **AirDrop**             | Seamlessly share files between Apple devices using peer-to-peer Wi-Fi  | Send photos from iPhone to Mac without cables/cloud                                             |
| **Universal Clipboard** | Copy on one device, paste on another                                   | Copy text on iPhone → Paste on Mac                                                               |
| **Handoff**             | Start a task on one device, continue on another                                                          | Open a doc on Mac → Continue editing on iPhone                                                  |
| **Continuity Camera**   | Use iPhone as high-quality webcam on Mac                                                                 | Enables features like center stage, desk view                                                   |
| **Sign/Scan with iPhone** | Use iPhone to scan/sign docs into macOS apps                                                           | Insert scanned photo or signature directly into documents                                       |
| **AirPlay/Sidecar**     | Cast or extend screen to/from other Apple devices                                                        | Use iPad as second monitor or mirror iPhone screen on Mac                                       |

---

## Time Management

- **Time blocking**: Schedule specific time slots for deep work or learning tasks (e.g., HTB modules)
- **Calendar App**:
  - Supports multiple calendars and color coding
  - Syncs across devices via iCloud
- **Focus Modes**:
  - Customize notifications and environment
  - Access from Control Center (macOS & iOS)

---

## Reminders

- Use for smaller tasks that don’t need time blocks
- Examples: 
  - Daily meds
  - Bill reminders
  - Simple to-do’s
- Use built-in **Reminders** app or third-party like **Fantastical**

---

## Note-Taking

- Use **Notes** for:
  - Yearly goals
  - Checklists
  - Project drafts
  - Training summaries
- Key features:
  - Tags, text formatting, real-time collaboration
  - Quick Notes (bottom-right corner gesture)
  - Handwriting recognition (with iPad/Apple Pencil)
  - iCloud sync across devices

---

## Cloud Storage

- **iCloud Drive** is native and synced
- Alternatives: Google Drive, OneDrive, Dropbox
- Cloud > External HDDs for mobility & security

---

## Multitasking

- **Full Screen (Green Button)**:
  - One app per screen (⌃+← / ⌃+→ to switch)
  - Hover to tile apps side-by-side
- **Stage Manager** (macOS 13+):
  - Groups windows by task
  - One-click switching between app clusters
- **Third-party Tools**:
  - **Moom**, **Magnet**, **BetterSnapTool**
  - Grid snapping, shortcut-based window arrangement

---

## Summary

macOS offers a wide range of built-in productivity features tailored to professionals and multitaskers. When combined with iCloud and other Apple services, these features allow seamless cross-device workflows, better time management, focused work environments, and powerful multitasking.

---

