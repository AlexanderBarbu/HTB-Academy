# 🐧 Linux Structure & Philosophy

## 📌 What is Linux?

- **Linux** is an operating system (OS), like Windows, macOS, iOS, or Android.
- It manages hardware resources and allows communication between hardware and software.
- It's **open-source**, **flexible**, and comes in many **distributions ("distros")** tailored to different use cases.
- Core tool for **cybersecurity professionals** due to its transparency and control.

---

## 🧠 Linux Philosophy

Linux follows a minimalist, modular approach with 5 core principles:

| Principle                                 | Description                                                                 |
|------------------------------------------|-----------------------------------------------------------------------------|
| **Everything is a file**                 | Most configuration is stored in text files.                                |
| **Small, single-purpose programs**       | Each tool does one thing well and can be reused.                           |
| **Chainability of programs**             | Tools can be combined to handle complex tasks.                             |
| **Avoid captive UIs**                    | Prefer command-line interface (shell) for full control.                    |
| **Config as text files**                 | e.g., /etc/passwd stores user data in plain text format.                |

---

## 🧩 Linux Components

| Component         | Description                                                                 |
|-------------------|-----------------------------------------------------------------------------|
| **Bootloader**     | Starts the OS boot process (e.g. GRUB in Parrot OS).                        |
| **OS Kernel**      | Core part of Linux, managing I/O and hardware at low level.                 |
| **Daemons**        | Background services (e.g. scheduling, printing) that run after boot/login.  |
| **OS Shell**       | CLI interface for interacting with the OS (e.g. Bash, Zsh, Fish, etc.).     |
| **Graphics Server**| Provides GUI capabilities via X-server.                                    |
| **Window Manager** | GUI desktop environments (e.g. GNOME, KDE, MATE, Cinnamon, etc.).           |
| **Utilities**      | Apps or scripts that perform specific tasks (for user or other programs).   |

---

## 🏗️ Linux Architecture (Layered View)

| Layer             | Description                                                                 |
|-------------------|-----------------------------------------------------------------------------|
| **Hardware**       | Physical components (CPU, RAM, disk, etc.).                                 |
| **Kernel**         | Manages hardware access, virtualizes resources, isolates processes.         |
| **Shell**          | Command-line interface to interact with the kernel.                         |
| **System Utilities**| Provide functionality and user-accessible tools of the OS.                 |

---

# 📂 Linux File System Hierarchy

Linux uses a **tree-like hierarchical structure**, standardized by the **Filesystem Hierarchy Standard (FHS)**. Everything starts from the root directory `/`, and all other directories are mounted underneath it.

---

## 🗂️ Top-Level Directories

| Path       | Description |
|------------|-------------|
| `/`        | The **root directory**. Contains the essential files needed to boot the OS before other filesystems are mounted. All other filesystems are mounted here as subdirectories. |
| `/bin`     | Contains **essential user command binaries** (e.g. `ls`, `cp`, `mv`). |
| `/boot`    | Contains the **bootloader**, **kernel image**, and other files required to boot Linux. |
| `/dev`     | Contains **device files** that represent hardware components. |
| `/etc`     | Contains **system-wide configuration files** for the OS and installed applications. |
| `/home`    | Contains **user home directories** (e.g. `/home/alex`). |
| `/lib`     | Contains **shared libraries** needed by binaries in `/bin` and `/sbin`. |
| `/media`   | Mount point for **removable media** (USB, CD-ROMs, etc.). |
| `/mnt`     | Temporary mount point for manually mounted filesystems. |
| `/opt`     | Optional software and **third-party applications** are installed here. |
| `/root`    | The **home directory of the root user**. |
| `/sbin`    | Contains **system administration binaries**, used by root. |
| `/tmp`     | Temporary files used by the OS and applications; usually cleared on reboot. |
| `/usr`     | Secondary hierarchy for **user utilities**, applications, libraries, and documentation. |
| `/var`     | Contains **variable data** such as logs, spool files, mail, and cache. |

---

## 🧭 Notes

- This structure is **common across modern Linux distributions**.
- Understanding it is crucial for system administration, scripting, and cybersecurity tasks.

---

# 🐧 Linux Distributions

## 📌 What is a Linux Distribution?

A **Linux distribution (or distro)** is an operating system built on top of the **Linux kernel**, bundled with a set of software packages, tools, and configurations for different use cases.

You can think of distros as **different branches of the same company**:
- Same **core employees** → the kernel and system components
- Same **company culture** → Linux philosophy (modularity, openness)
- But different **products & services** → packages, configs, UI

---

## 🖥️ Why So Many Distros?

Each distro is tailored for different needs:
- **Desktops**: User-friendly interfaces, multimedia, customization
- **Servers**: Stability, security, long-term support
- **Cybersecurity**: Penetration testing tools, low-level access
- **Embedded/Mobile**: Lightweight footprint, specific hardware

---

## 🔥 Popular Linux Distributions (General Purpose)

| Distro                     | Use Case                          |
|----------------------------|-----------------------------------|
| **Ubuntu**                | Desktop users, beginners          |
| **Fedora**                | Developers, desktop users         |
| **CentOS**                | Servers, enterprise (now replaced by Alma/Rocky) |
| **Debian**                | Stability-focused, servers        |
| **Red Hat Enterprise Linux (RHEL)** | Paid enterprise computing |

---

## 🛡️ Distributions in Cybersecurity

Cybersecurity pros prefer distros that are:
- Open source
- Customizable
- Packed with security tools

**Common Security-Focused Distros:**

- **Kali Linux** 🥷
- **Parrot OS**
- **BlackArch**
- **BackBox**
- **Pentoo**
- **Ubuntu / Debian (configured manually)**
- **Raspberry Pi OS** (for hardware projects)

---

## 🧠 Debian (In-Depth)

**Debian** is a respected Linux distro known for:
- 🧱 **Stability & Reliability**
- 🔄 **APT package manager**
- 🔐 Strong **security track record**

### 🔧 Key Features

- **Long-term support (LTS)**: Security patches for up to 5 years
- **Flexible & customizable**
- Ideal for: Desktops, servers, embedded systems
- Great for users who want **full control**

### ⚠️ Learning Curve

- More complex to configure than Ubuntu
- Requires understanding of system internals
- Without proper depth, simple tasks may feel harder

But:
> *The more you learn it, the less time you waste.*

---

## ✅ Summary

| Distro       | Strengths                                  |
|--------------|--------------------------------------------|
| **Kali Linux** | Best for penetration testing               |
| **Ubuntu**     | Easy to use, beginner-friendly             |
| **Debian**     | Reliable, secure, long-term support        |
| **RHEL / CentOS** | Enterprise-grade, supported by Red Hat    |
| **Parrot OS**  | Lightweight, privacy-focused, cybersec     |
| **BlackArch**  | Massive repo of hacking tools (advanced)   |

Linux distros give you freedom to pick exactly what fits your goals — whether you're setting up a web server, reverse engineering malware, or just learning CLI.

---

# 💻 Introduction to Shell

## 🧠 Why Learn the Shell?

- The shell is essential to interacting with Linux systems, especially **servers**.
- Many **web servers** and **infrastructure machines** run Linux due to its **stability and low error rate**.
- Mastering the shell means gaining full control over the system — far beyond what a GUI offers.

---

## 🖥️ What Is a Shell?

- A **shell** (also called terminal or command line) is a **text-based interface** between the user and the **Linux kernel**.
- It allows you to:
  - Navigate directories
  - Manage files
  - Monitor and control system processes
  - Run automation scripts

### 🧪 Visual Analogy:
> Think of the **shell** as the **server room** of a building, and the **terminal** as the **reception desk** where you deliver instructions.

---

## 🖼️ Terminal Emulators

**Terminal emulators** are software programs that:
- Emulate a physical terminal within a GUI
- Provide access to the shell in a graphical environment

### 🧩 Multiplexers (e.g., `tmux`):
- Allow multiple terminals in one window
- Useful for:
  - Splitting screens
  - Working in multiple directories
  - Creating isolated workspaces

🧪 *Example:*  
A `tmux` setup might show three panes:
- One with `BloodHound` files  
- One with `Impacket`  
- One with `SecLists`  
All controlled from the same terminal window.

---

## 🐚 Types of Shells

The **most common shell** in Linux is:

- **BASH (Bourne Again Shell)** – part of the GNU project  
  - Supports scripting
  - Automates workflows
  - Offers powerful built-in tools for file/system interaction

### 🔄 Other popular shells:

| Shell | Description |
|-------|-------------|
| **Zsh**  | Feature-rich, customizable, used by macOS |
| **Fish** | User-friendly, smart auto-suggestions |
| **Ksh**  | KornShell, used in legacy Unix systems |
| **Tcsh/Csh** | C-style syntax, used in older systems |

---

## ⚙️ Key Benefits of Using the Shell

- Automate tasks with scripts
- Greater system visibility and control
- Faster execution of repetitive tasks
- Essential for cybersecurity, scripting, and penetration testing

---

# 💬 Bash Prompt (PS1) Description

## 🧠 What is the Bash Prompt?

- The **Bash prompt** is the line that appears in the terminal to indicate that the system is ready for input.
- By default, it shows:
  - `username` – who you are
  - `hostname` – the computer name
  - `current working directory`
- The prompt usually ends in:
  - `$` for regular users
  - `#` for root (privileged user)


---

## 📍 Prompt Format Examples

```bash
user@hostname:~$        # regular user in home directory
root@htb:/htb#          # root user in /htb directory
$                       # prompt with missing info (PS1 not set)
#                       # same, but with root privileges

| Code           | Description                            |
| -------------- | -------------------------------------- |
| `\u`           | Username                               |
| `\h`           | Hostname (short)                       |
| `\H`           | Full hostname                          |
| `\w`           | Full current working directory path    |
| `\W`           | Base name of current working directory |
| `\t`           | Time (HH\:MM\:SS, 24-hour format)      |
| `\@`           | Time (AM/PM format)                    |
| `\d`           | Date (e.g. "Mon Feb 6")                |
| `\D{%Y-%m-%d}` | Custom date format (e.g. "2025-07-10") |
| `\j`           | Number of background jobs              |
| `\n`           | Newline                                |
| `\s`           | Name of the shell                      |

```
---

#  🆘  Getting Help in the Linux Shell

## 🧠 Why It's Important

- You’ll often come across commands or tools you don’t know by heart.
- Getting help quickly and efficiently is **key to navigating Linux**.
- There are **multiple built-in ways** to access help and documentation for almost every command.

---

## 🧾 `man` – Manual Pages

- Shows **detailed documentation** about a command.
- Includes usage, syntax, parameters, and examples.

## Prompt recap

| Method             | Description                             |
| ------------------ | --------------------------------------- |
| `man`              | Full manual for the tool                |
| `--help`           | Quick overview of options               |
| `-h`               | Short help (tool-dependent)             |
| `apropos`          | Search man page descriptions by keyword |
| `explainshell.com` | Online breakdown of complex commands    |

---

# 🧠 System Information (Linux Basics)

Understanding your system is **essential** — both for basic Linux usage and for security assessments.  
These commands help you **enumerate system info**, which is especially useful in:

- 🧪 Privilege escalation
- 🔍 Vulnerability assessments
- 🔧 Debugging / troubleshooting

---

## 🖥️ Basic System & User Info

| Command     | Description                                       |
|-------------|---------------------------------------------------|
| `whoami`    | Displays current **username**                    |
| `id`        | Shows **user ID (UID), group ID (GID)** and group memberships |
| `hostname`  | Shows or sets the **systems hostname**          |
| `uname`     | Prints **kernel & system info** (add `-a` for all info) |
| `pwd`       | Prints the **current working directory**         |

---

## 🌐 Network & Interface Info

| Command     | Description                                       |
|-------------|---------------------------------------------------|
| `ifconfig`  | Displays or configures **network interfaces** (older) |
| `ip a`      | Modern replacement for `ifconfig` – shows IP, interface info |
| `netstat`   | Displays **network connections**, routing tables, etc. |
| `ss`        | Modern alternative to `netstat`, focused on **sockets**

---

## 👥 Users & Sessions

| Command     | Description                                       |
|-------------|---------------------------------------------------|
| `who`       | Shows **currently logged-in users**              |
| `env`       | Displays current **environment variables**       |

---

## 💽 Devices & Storage

| Command     | Description                                       |
|-------------|---------------------------------------------------|
| `lsblk`     | Lists all **block storage devices**              |
| `lsusb`     | Lists **USB devices** connected to the system    |
| `lspci`     | Lists **PCI devices** (e.g. network cards, GPUs) |
| `lsof`      | Lists all **open files** (useful for debugging, forensics) |

---

## ⚙️ Processes

| Command     | Description                                       |
|-------------|---------------------------------------------------|
| `ps`        | Displays **running processes** (`ps aux` for full list) |

---

## 🛠️ Pro Tips

- Always run:
  ```bash
  <command> -h
  <command> --help
  man <command>

---

# 🔐 Logging In via SSH

## 📌 What is SSH?

**SSH (Secure Shell)** is a protocol used to securely access and manage remote systems via a command-line interface. It's:

- Installed by default on most Linux and Unix systems  
- Used by sysadmins for remote configuration  
- Lightweight, reliable, and doesn't require a GUI

---

## 🚀 Connecting via SSH

Basic syntax:
```bash
ssh htb-student@[IP_ADDRESS]
```

You’ll use this often throughout HTB modules and labs to connect to target systems.

### 📟 Essential Commands After Login

- hostname
Prints the name of the machine you're logged into:
✅ Useful for identifying the remote host during a session.

- whoami
Returns the current user:
✅ Helps verify access level (e.g., regular user or root)
✅ First step after gaining a reverse shell in an engagement

- id
Prints user ID, group ID, and group memberships:

Example output:
uid=1000(cry0l1t3) gid=1000(cry0l1t3) groups=1000(cry0l1t3),1337(hackthebox),4(adm),27(sudo)
✅ Useful to identify special privileges (e.g., sudo, adm, hackthebox)

- uname
Prints system info. Basic usage: uname -a

Example output:

Linux box 4.15.0-99-generic #100-Ubuntu SMP Wed Apr 22 20:32:56 UTC 2020 x86_64 GNU/Linux
To isolate the kernel release (useful for exploit lookups):

uname -r
✅ Can be used to google for kernel-specific exploits
✅ E.g., search "4.15.0-99-generic exploit"

### 🧠 Why It Matters

These commands help verify your current access level
Critical in privilege escalation and situational awareness
Study their man pages (man id, man uname, etc.) to learn hidden flags and use cases

---

# 📂 Linux Navigation - HTB Notes

## 🧭 Overview

- Navigation in Linux is like using a mouse in Windows.
- Learn how to **move between directories**, **list/edit/move/delete files**, **use shortcuts**, **handle redirects**, and understand **file descriptors**.
- Always test commands in a local VM snapshot to avoid breaking the system.

---

## 📍 Current Directory

- `pwd` → Print the current working directory
  ```bash
  pwd
  # /home/cry0l1t3

## 📄 Listing Directory Contents

- **`ls`** → Lists files/directories in the current folder
- **`ls -l`** → Long listing format with permissions, owner, size, etc.
- **`ls -la`** → Long listing including hidden files (starting with .)

## 🫥 Hidden Files

- Files starting with . are hidden
- Use ls -la to show them

## 🗂️ List Other Directory Contents

- You can list contents without cd:
ls -l /var/

## 🚶 Directory Navigation

- **`cd`** → Change directory
- **`cd /full/path`** → Go directly to a path
- **`cd .. `**→ Move up one level
- **`cd - `**→ Go back to previous directory

- ⌨️ TAB Autocomplete

**` . `**→ Current directory
**` .. `**→ Parent directory
ls -la /dev/shm
cd ..

## 🧹 Clear Terminal

**`clear`** → Clears the terminal screen
Ctrl + L → Keyboard shortcut for clear

## 🕘 Command History

↑ / ↓ → Browse previous commands
Ctrl + R → Search command history with keywords

---

# 📁 Working with Files and Directories

## 🧾 Key Concept

- Unlike Windows, Linux encourages **command-line interaction** with files.
- Instead of using GUI tools like Explorer, we can **create, access, and modify files** directly from the terminal.

---

## ⚙️ Why Use the Terminal?

- **Faster & more efficient** than GUI.
- No need for editors like `vim` or `nano` for basic file edits.
- Ability to:
  - Access files quickly with simple commands
  - Use **regex** for targeted edits
  - Chain multiple commands for batch file handling
  - Redirect output (`>` `>>`) and automate workflows

---

## 🔥 Advantages of CLI File Management

- Interactive and **scriptable**
- Can process **many files at once**
- Saves time vs. doing edits manually in GUI
- Ideal for automation, scripting, and system maintenance

---

# 🛠️ Create, Move, and Copy - HTB Notes

## 🚀 Starting Point

- Before running file operations, connect to the target via **SSH**.

---

## 📄 Create a File

- **`touch <filename>`** → Creates an empty file
  
## 📁 Create a Directory

- **`mkdir <dirname>`** → Creates a single directory

- **`mkdir -p <path>`** → Creates nested directories, including parents if needed

- **`-p`** is useful when building directory structures in one command.

---

# 🛠️ Create, Move, and Copy (Part 2) - HTB Notes

## 🌲 View Directory Structure

- Use `tree` to visualize folder hierarchy:

Example output:
.
├── info.txt
└── Storage
    └── local
        └── user
            └── documents

4 directories, 1 file

## 📄 Create Files in Nested Directories

Use relative path with **` ./ `**to start from the current directory:
touch ./Storage/local/user/userinfo.txt
Resulting structure:

.
├── info.txt
└── Storage
    └── local
        └── user
            ├── documents
            └── userinfo.txt

4 directories, 2 files
✏️ Rename or Move Files with mv

Syntax:
- **` mv <source> <destination> `**

Rename file:

**` mv info.txt information.txt `**

---

# ✏️ Editing Files

## 🔍 Overview
- After creating files and directories, we need to **edit** them.
- Common editors in Linux: **Vi**, **Vim**, **Nano**.
- We'll start with **Nano** (simple and beginner-friendly), then **Vim** (powerful and modal).

## 🖊️ Using Nano

- Open (or create) a file with **nano**:
  ```bash
  nano notes.txt

- This opens the Nano editor and lets you edit text immediately.

### ✅ Nano Basics

- Write text directly in the editor.
- Important shortcuts (the ^ symbol means CTRL):
Shortcut	Action
- **`CTRL + W`**	Search text
- **`CTRL + O`**	Save file
- **`CTRL + X`**	Exit Nano
- **`CTRL + G`**	Help

## 🔐 Important Files for Pentesters

- **` /etc/passwd `** → Holds user info (username, UID, GID, home dir).
Historically stored password hashes (now in /etc/shadow).
Misconfigured permissions = potential privilege escalation.

## ⚡ Vim - Vi Improved

- Vim is an open-source, modal text editor.
- Modal concept → Different modes for different actions.
  
### ✅ Vim Modes

Mode	Description: 

- Normal	Default mode; commands (move, delete, copy, etc.)
- Insert	Insert text into buffer
- Visual	Select text visually for operations
Command	Enter commands like :q, :w, :sort, etc.
Replace	Overwrite existing text

## 🎓 VimTutor

- Practice Vim with built-in tutorial:
- Approx time: 25-30 mins.
- Covers essential commands for beginners.

## 🔑 Key Takeaways
- Nano = Simple, beginner-friendly editor.
- Vim = Powerful, modal, ideal for advanced editing.
- Important files (/etc/passwd, /etc/shadow) matter for security.
- Always check file permissions for privilege escalation opportunities.

---

# 🔍 Find Files and Directories

## ✅ Why It Matters
- When accessing a Linux system, it's essential to **quickly find files and directories**.
- Common scenarios:
  - Locate **configuration files**
  - Find **scripts created by admins or users**
  - Check system files for **security issues**
- No need to manually browse every folder—Linux provides tools for this.

## 📌 `which` Command

- **Purpose:** Displays the path of an executable that would run if the command is executed.
- **Usage:** Helps verify if programs like `curl`, `netcat`, `wget`, `python`, `gcc` are available.
  
### ✅ Syntax:
```bash
which <program>
```
---

## **Find Command in Linux**

- The `find` command is a powerful utility for **searching files and directories** in Linux. It supports advanced filtering options to locate files based on multiple criteria.


### **Purpose**
- Locate **files and directories** within a specified location.
- Apply **filters** such as:
  - **File size**
  - **Modification date**
  - **Type** (file or directory)


### **Syntax**
```bash
find <location> <options>
```

- **`<location>`** : Directory path to start the search (e.g., /home, . for current directory).
- **`<options>`**: Flags and conditions to filter results.

- Key Features: 
  - Supports searching by:
    - Name
    - Type (file, directory, symbolic link)
    - Permissions
    - Date modified
- Can execute actions on found files (e.g., delete, move, print).

---

## **Find Command Options Explained**

When using the `find` command, several options can refine the search and define what actions to perform. Below is an explanation of the common options used:

---

### **Options and Their Descriptions**

- **`-type f`**  
  Defines the type of the searched object. Here, `f` stands for **file**.

- **`-name *.conf`**  
  Searches for files matching a specific name pattern. The asterisk (`*`) acts as a wildcard, meaning **all files with the `.conf` extension**.

- **`-user root`**  
  Filters files that are owned by the **root user**.

- **`-size +20k`**  
  Finds files **larger than 20 KiB**. The `+` sign indicates "greater than."

- **`-newermt 2020-03-03`**  
  Lists files **modified after** the specified date (`2020-03-03`).

- **`-exec ls -al {} \;`**  
  Executes a command on each result.  
  - `{}` acts as a placeholder for the found file.  
  - `\;` ends the `-exec` command. The backslash escapes the semicolon so it isn’t interpreted by the shell.

- **`2>/dev/null`**  
  Redirects **STDERR (error messages)** to the null device (`/dev/null`) to hide errors.  
  *Note:* This is **not an option of `find`** but a shell redirection.

---

### **Example**
```bash
find /etc -type f -name "*.conf" -user root -size +20k -newermt 2020-03-03 -exec ls -al {} \; 2>/dev/null
```

### **Command Breakdown**

This command performs the following:

- **Searches under** `/etc`
- **For files** (`-type f`)
- **Named** `*.conf`
- **Owned by** `root`
- **Larger than** `20 KiB`
- **Modified after** `2020-03-03`
- **Executes** `ls -al` on each result
- **Hides any errors** by redirecting them to `/dev/null`

---

## **Locate Command in Linux**

The `locate` command provides a **faster way to search for files and directories** compared to `find`. Unlike `find`, which scans the filesystem in real-time, `locate` searches a **local database** containing file and folder paths.

---

### **Key Characteristics**
- **Works with a pre-built database** instead of real-time scanning.
- **Faster than `find`** because it doesn’t traverse the filesystem during the search.
- Requires **database updates** to reflect recent changes.

---

### **Update the Database**
To ensure the `locate` database is up-to-date:
```bash
sudo updatedb
```

### **Limitations**
- Fewer filtering options than `find` (e.g., cannot filter by size, date, or ownership).
- Best used for quick searches by name, not for detailed filtering.

### **When to Use**
- Use **`locate`** for speed when you just need to find files by name.
- Use **`find`** when advanced filtering is required (size, permissions, date, etc.).

