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

### **Key Characteristics**
- **Works with a pre-built database** instead of real-time scanning.
- **Faster than `find`** because it doesn’t traverse the filesystem during the search.
- Requires **database updates** to reflect recent changes.

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

---

# **File Descriptors and Redirections**

A **file descriptor (FD)** in Unix/Linux is a reference managed by the kernel that represents an open file, socket, or any I/O resource. It acts as a **unique identifier** for an active I/O connection, allowing the operating system to handle **read/write operations** efficiently.

---

### **Analogy**
Think of a file descriptor as a **ticket number** at a coatroom:
- The ticket (**file descriptor**) represents your connection to your coat (**file/resource**).
- When you need your coat (**I/O operation**), you show the ticket to the attendant (**OS**) who knows where it is.
- Without the ticket, the OS wouldn't know which resource to interact with.

---

### **Default File Descriptors in Linux**
- **STDIN** (Standard Input) → **FD 0** → Input stream
- **STDOUT** (Standard Output) → **FD 1** → Output stream
- **STDERR** (Standard Error) → **FD 2** → Error output stream

---

### **STDIN and STDOUT Example**
Using the `cat` command:
```bash
cat
```

- **`STDIN (FD 0)`** : The user provides input (e.g., SOME INPUT).
- After pressing [ENTER], the input is echoed back to the terminal as:
- **`STDOUT (FD 1)`**: Displays the input text.

- Flow:
  - Keyboard → [STDIN] → cat → [STDOUT] → Terminal


---

## **STDOUT and STDERR**

When using commands like `find`, Linux differentiates between:
- **STDOUT (FD 1)** → Standard Output
- **STDERR (FD 2)** → Standard Error

For example, if a command returns a valid result and also "Permission denied" messages, the valid results go to **STDOUT**, and the errors go to **STDERR**.

---

### **Redirecting STDERR**
We can redirect **errors** (FD 2) to the null device (`/dev/null`) to hide them. The null device discards all data sent to it.

---

### **Redirecting STDOUT to a File**
We can redirect **standard output** to a file. This ensures only the valid results are written, excluding errors if they were previously redirected.

---

### **Redirecting STDOUT and STDERR to Separate Files**
To be precise, **STDOUT** and **STDERR** can be redirected to **different files**:
- FD 1 (**STDOUT**) → one file
- FD 2 (**STDERR**) → another file

---

### **Redirecting STDIN**
Using `<` redirects **standard input** (FD 0) from a file instead of typing it manually. This allows a command like `cat` to read data from a file as input.

---

### **Appending STDOUT to an Existing File**
- `>` creates a new file or overwrites an existing one without confirmation.
- `>>` **appends** the output to an existing file instead of overwriting it.

---

### **Redirecting STDIN Stream with EOF**
Using `<<` allows providing **input through a stream**. The End-Of-File (**EOF**) marker indicates the end of the input stream. This is often used with commands like `cat` to create files from inline input.

---

## **Pipes**

**Pipes (`|`)** are another way to redirect **STDOUT** by sending the output of one command directly into another command as **STDIN**. They are commonly used for **chaining commands** and **processing data efficiently**.

---

### **How Pipes Work**
- The **first command's STDOUT** becomes the **second command's STDIN**.
- Useful for applying filters or additional processing without creating intermediate files.

---

### **Common Usage Example**
- Using `grep` to filter results from `find`:
  - `find` lists files.
  - `grep` filters the output according to a defined pattern.
- Additional example: piping output through `wc` to count the lines of the filtered results.

---

### **Chaining Multiple Commands**
- Pipes can be chained multiple times:
  - Example: `command1 | command2 | command3`
- Each command processes the output of the previous one.

---

### **Why It Matters**
- Enables **structured commands** for extracting **only the needed information**.
- Reduces unnecessary steps and intermediate files.
- Provides **flexibility and precision** in managing I/O streams.

---

## **In Summary**

- **File Descriptors (FD):**  
  Numeric identifiers for I/O streams managed by the OS.  

- **Default FDs:**  
  | FD | Stream  | Purpose                |
  |----|---------|------------------------|
  | 0  | STDIN   | Input (keyboard, files) |
  | 1  | STDOUT  | Normal output (screen) |
  | 2  | STDERR  | Error messages         |

- **Redirections:**  
  - `>` : Redirect STDOUT to file (overwrite)  
  - `>>`: Append STDOUT to file  
  - `<` : Redirect file content to STDIN  
  - `2>`: Redirect STDERR  

- **Pipes (`|`):**  
  Chain commands by sending one command's STDOUT as another's STDIN.  

- **Key Idea:**  
  Control **where input comes from and where output goes** → enables **automation, precision, and efficient workflows** in Linux.
  By combining **file descriptors**, **redirections**, and **pipes**, we gain control over:
  - How input and output flows between **files**, **commands**, and **processes**.
  - Increased **efficiency** and **productivity** when working in Linux environments.

---

# **Filter Contents**

When working in Linux, it's often useful to **read files directly from the command line** without opening a text editor. This approach is essential for **quick analysis of large files**, such as logs or system configuration files.

---

## **Pagers: `more` and `less`**
- **Purpose:**  
  Both tools allow viewing file contents **one screen at a time** without modifying the file.
- **Key Features:**
  - Scroll through large files interactively.
  - Navigate forward and backward.
  - Search for text within the file.
- **Difference:**
  - `less` is generally more feature-rich and efficient than `more`.

### **Why Use Pagers?**
- Efficient for **large files** that do not fit on one screen.
- Ideal for **log analysis** or reviewing long text data.
- Does not require loading the entire file into memory at once.
  
### **Before Filtering**
- Pagers prepare us for **handling redirected output** from commands.
- They act as foundational tools before moving on to advanced filtering and text-processing utilities like `grep`, `sort`, and `awk`.

### **Example Scenario**
- Viewing `/etc/passwd`:
  - This file stores user account details (username, user ID, group ID, home directory, default shell).
- Instead of opening it in a text editor, a pager lets us inspect it **quickly and interactively**.

### **Key Takeaway**
Pagers like `more` and `less` are essential for **navigating and analyzing file content** efficiently in Linux. They provide the groundwork for filtering and processing data directly from the command line.

## **Filtering and Viewing File Contents**

When working with Linux systems, we often need to **inspect, navigate, and filter large files or command outputs**. Several tools make this efficient and flexible, allowing us to avoid opening text editors and enabling automation in scripts.

---

### **1. Less**
- **Purpose:** A pager like `more` but more feature-rich.
- **Features:**
  - Navigate forward and backward.
  - Search text inside the file.
  - Exits cleanly without leaving output in the terminal (unlike `more`).
- **Use Case:** Ideal for large files and logs where quick navigation and searching are needed.

### **2. Head**
- Displays the **first lines** of a file (default: 10 lines).
- **Purpose:** Quick check of file headers or beginning content.
- **Use Case:** Preview configuration files or logs without opening the entire file.

### **3. Tail**
- Displays the **last lines** of a file (default: 10 lines).
- **Purpose:** Monitor recent entries, e.g., logs.
- **Use Case:** Often combined with `tail -f` for live log monitoring.

### **4. Sort**
- Organizes text data **alphabetically or numerically**.
- **Purpose:** Create an ordered view of unsorted outputs.
- **Use Case:** Sorting user lists, logs, or command results for easier analysis.

### **5. Grep**
- Searches for lines **matching a specific pattern**.
- **Key Features:**
  - **Direct match:** Display lines containing a pattern.
  - **Exclusion:** Use `-v` to show lines that **do NOT** match the pattern.
  - Supports regex for advanced filtering.
- **Use Case:** Find users with `/bin/bash` shell, filter logs, or exclude disabled accounts.

---

## **Why These Tools Matter**
- They allow **fast inspection** of files and output.
- Enable **powerful filtering** without opening editors.
- Essential for automation, scripting, and efficient troubleshooting.

---

### **Key Takeaways**
- **Less:** Navigate large files interactively.
- **Head/Tail:** Inspect start or end of files.
- **Sort:** Arrange data for clarity.
- **Grep:** Extract or exclude based on patterns.
- Together, these tools streamline data analysis and command-line productivity.

---

# **Advanced Text Processing and Filtering Tools**

When dealing with complex data in Linux, filtering and formatting outputs is essential for clarity and efficiency. Below are key tools that help manipulate and process text directly from the command line.

### **1. Cut**
- **Purpose:** Extract specific fields from lines based on a delimiter.
- **Options:**
  - `-d` → Define the delimiter (e.g., `:`).
  - `-f` → Specify which field(s) to display.
- **Use Case:** Extract usernames from `/etc/passwd`.

### **2. Tr (Translate)**
- **Purpose:** Replace or remove characters in text.
- **Example Functionality:**
  - Replace delimiters with spaces.
  - Remove unwanted characters for cleaner output.
- **Use Case:** Convert colon-separated values into space-separated format.

### **3. Column**
- **Purpose:** Format text into **aligned columns** for better readability.
- **Option:**
  - `-t` → Creates a table-like layout.
- **Use Case:** Present structured data from command outputs in a tabular form.

### **4. Awk**
- **Purpose:** A text-processing tool for extracting and manipulating data fields.
- **Key Features:**
  - `$1` → First field.
  - `$NF` → Last field.
  - Combine fields for custom outputs.
- **Use Case:** Display usernames with their default shells.

### **5. Sed (Stream Editor)**
- **Purpose:** Perform text transformations using patterns and regular expressions.
- **Common Use Case:** Replace strings globally within lines.
- **Flags:**
  - `s` → Substitute command.
  - `g` → Global replacement on the line.
- **Example Functionality:** Replace every occurrence of a word across all lines.

### **6. Wc (Word Count)**
- **Purpose:** Count lines, words, or characters.
- **Option:**
  - `-l` → Count lines only.
- **Use Case:** Quickly determine the number of filtered results.

---

### **Practice and Exploration**
- The Linux command line offers a wide range of tools for filtering, formatting, and transforming data.
- Recommended approach:
  - Use `man <tool>` or `<tool> --help` for detailed options.
  - Experiment regularly to build familiarity.
- These tools become intuitive with practice and enable efficient workflows when processing large datasets.

---

### **Key Takeaways**
- **Cut:** Extract specific fields.
- **Tr:** Replace or remove characters.
- **Column:** Organize output into a table format.
- **Awk:** Flexible field manipulation and printing.
- **Sed:** Search and replace text using regex.
- **Wc:** Count lines, words, or characters.
- Together, these utilities provide a powerful toolkit for text processing in Linux.

---

# Regular Expressions

Regular expressions (RegEx) are like the art of crafting precise blueprints for searching patterns in text or files. They allow you to find, replace, and manipulate data with incredible precision. Think of RegEx as a highly customizable filter that lets you sift through strings of text, looking for exactly what you need — whether it's analyzing data, validating input, or performing advanced search operations.

At its core, a regular expression is a sequence of characters and symbols that together form a search pattern. These patterns often involve special symbols called metacharacters, which define the structure of the search rather than representing literal text. For example, metacharacters allow you to specify whether you're searching for digits, letters, or any character that fits a certain pattern.

RegEx is available in many programming languages and tools, such as grep or sed, making it a versatile and powerful tool in our toolkit.

---

## Grouping

Regex supports grouping search patterns using three main types of brackets:

### Grouping Operators

| Operator   | Description                                                                 |
|------------|-----------------------------------------------------------------------------|
| `(a)`      | Round brackets are used to group parts of a regex pattern for joint matching |
| `[a-z]`    | Square brackets define a character class — match any one of the listed chars |
| `{1,10}`   | Curly brackets define quantifiers — how many times the pattern should repeat |
| `|`        | OR operator — matches if **either** of the expressions is present           |
| `.*`       | AND-like chaining — matches if **both** patterns exist in the given order    |

---

## Practice Tasks

Use the `/etc/ssh/sshd_config` file to solve the following:

1. Show all lines that do **not** contain the `#` character.
2. Search for all lines that contain a word that **starts with** `Permit`.
3. Search for all lines that contain a word **ending with** `Authentication`.
4. Search for all lines containing the word `Key`.
5. Search for all lines that **begin with** `Password` and also contain `yes`.
6. Search for all lines that **end with** `yes`.

---

# Permission Management

In Linux, permissions are like keys that control access to files and directories. These permissions are assigned to both users and groups, much like keys being distributed to specific individuals and teams within an organization. Each user can belong to multiple groups, and being part of a group grants additional access rights, allowing users to perform specific actions on files and directories.

Every file and directory has an **owner (user)** and is associated with a **group**. The permissions for these files are defined for both the owner and the group, determining what actions — like reading, writing, or executing — are allowed. When a user creates a new file or directory, it automatically becomes owned by them and is associated with their primary group.

Linux permissions act like a rule-based system that dictates who can access or modify specific resources, ensuring both **security** and **collaboration** across the system.

---

## Directory Access and Execute Permission

To access a directory, a user must have **execute (`x`) permission** on it. Without it:

- You cannot **enter** or **traverse** the directory.
- You may still see the directory exists but will encounter **“Permission Denied”** when trying to interact with its contents.

Execute permission on a directory is like a hallway key — it lets you move through the space but **not** necessarily see or change what's inside unless you also have **read (`r`)** and/or **write (`w`)** permissions.

---

## File Permissions Summary

Linux permissions are based on the **octal number system**, with **three main types** of permissions:

| Symbol | Permission | Description                                 |
|--------|------------|---------------------------------------------|
| `r`    | Read       | View contents of a file or list a directory |
| `w`    | Write      | Modify or delete contents                   |
| `x`    | Execute    | Run files or enter directories              |

Permissions apply to three categories:

- **User** (u): The file owner
- **Group** (g): Members of the file’s group
- **Others** (o): Everyone else

---

## Example: File Permission Breakdown

-rwxrw-r-- 1 root root 1641 May 4 23:42 /etc/passwd
│ │ │ │ │ │ │ │ └── Timestamp
│ │ │ │ │ │ └────────────── File Size
│ │ │ │ │ └─────────────────── Group
│ │ │ │ └──────────────────────── Owner
│ │ │ └──────────────────────────── Hard Links
│ │ └─────────────────────────────── Permissions (Others)
│ └────────────────────────────────── Permissions (Group)
└──────────────────────────────────── Permissions (Owner)


- `-`: Regular file (not directory or symlink)
- `rwx`: Owner has read, write, execute
- `rw-`: Group has read, write
- `r--`: Others have read only

---

# Modifying Directories

- To **traverse** a directory: `x` permission required
- To **list contents**: `r` permission required
- To **create/delete/rename** inside: `w` permission required

- **Note:** Changing file contents still depends on **file-level permissions**, not the directory.

---

# Change Permissions

To modify permissions on files or directories, use the `chmod` command along with:

- **u**: user (owner)
- **g**: group
- **o**: others
- **a**: all users
- **+ / -**: add or remove permission

Example:  
To add read permission to all users for a file:

- `chmod a+r filename`

You can also use **octal notation**:

| Symbol | Binary | Octal | Permission |
|--------|--------|-------|------------|
| r      | 100    | 4     | read       |
| w      | 010    | 2     | write      |
| x      | 001    | 1     | execute    |

Example:

- `chmod 754 shell`

Which sets:

- **7 (rwx)** → owner
- **5 (r-x)** → group
- **4 (r--)** → others

---

## Change Owner

To change ownership of a file or directory, use the `chown` command:
``` bash
chown <user>:<group> <file_or_directory>
```

- This assigns both user and group ownership of `shell` to `root`.

---

# SUID & SGID

Linux supports **special permissions** for executable files:

- **SUID** (Set User ID): Executes the file as the **file owner**
- **SGID** (Set Group ID): Executes the file with the **group’s permissions**

### Indicators

- SUID: `s` in **user** execute bit (e.g. `rwsr-xr-x`)
- SGID: `s` in **group** execute bit (e.g. `rwxr-sr-x`)

### Risks

- Programs with SUID/SGID can **elevate privileges**
- Misconfigured SUID binaries can lead to **full system compromise**

🔒 **Important:** Use SUID/SGID **with caution**. Tools like [GTFObins](https://gtfobins.github.io) document known binaries that can be exploited if misconfigured.

---

### Sticky Bit

- Sticky bits in Linux are like locks on files within shared spaces. When set on a directory, the sticky bit adds an extra layer of security, ensuring that only certain individuals can modify or delete files, even if others have access to the directory.

- Imagine a communal workspace where many people can enter and use the same tools, but each person has their own drawer that only they (or the manager) can open. The sticky bit acts like a lock on these drawers, preventing anyone else from tampering with the contents. In a shared directory, this means only the file's owner, the directory's owner, or the root user (the system administrator) can delete or rename files. Other users can still access the directory but can’t modify files they don’t own.

- This feature is especially useful in shared environments, like public directories, where multiple users are working together. By setting the sticky bit, you ensure that important files aren’t accidentally or maliciously altered by someone who shouldn’t have the authority to do so, adding an important safeguard to collaborative workspaces.

- If the sticky bit is capitalized (`T`), this means that all other users do not have execute (`x`) permissions and, therefore, cannot see the contents of the folder nor run any programs from it. The lowercase sticky bit (`t`) indicates that execute permissions have been set along with the sticky bit.

---



