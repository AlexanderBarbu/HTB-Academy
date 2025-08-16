# 📚 Table of Contents
- [📚 Table of Contents](#-table-of-contents)
- [🐧 Linux Structure \& Philosophy](#-linux-structure--philosophy)
  - [📌 What is Linux?](#-what-is-linux)
  - [🧠 Linux Philosophy](#-linux-philosophy)
  - [🧩 Linux Components](#-linux-components)
  - [🏗️ Linux Architecture (Layered View)](#️-linux-architecture-layered-view)
- [📂 Linux File System Hierarchy](#-linux-file-system-hierarchy)
  - [🗂️ Top-Level Directories](#️-top-level-directories)
  - [🧭 Notes](#-notes)
- [🐧 Linux Distributions](#-linux-distributions)
  - [📌 What is a Linux Distribution?](#-what-is-a-linux-distribution)
  - [🖥️ Why So Many Distros?](#️-why-so-many-distros)
  - [🔥 Popular Linux Distributions (General Purpose)](#-popular-linux-distributions-general-purpose)
  - [🛡️ Distributions in Cybersecurity](#️-distributions-in-cybersecurity)
  - [🧠 Debian (In-Depth)](#-debian-in-depth)
    - [🔧 Key Features](#-key-features)
    - [⚠️ Learning Curve](#️-learning-curve)
  - [✅ Summary](#-summary)
- [💻 Introduction to Shell](#-introduction-to-shell)
  - [🧠 Why Learn the Shell?](#-why-learn-the-shell)
  - [🖥️ What Is a Shell?](#️-what-is-a-shell)
    - [🧪 Visual Analogy:](#-visual-analogy)
  - [🖼️ Terminal Emulators](#️-terminal-emulators)
    - [🧩 Multiplexers (e.g., `tmux`):](#-multiplexers-eg-tmux)
  - [🐚 Types of Shells](#-types-of-shells)
    - [🔄 Other popular shells:](#-other-popular-shells)
  - [⚙️ Key Benefits of Using the Shell](#️-key-benefits-of-using-the-shell)
- [💬 Bash Prompt (PS1) Description](#-bash-prompt-ps1-description)
  - [🧠 What is the Bash Prompt?](#-what-is-the-bash-prompt)
  - [📍 Prompt Format Examples](#-prompt-format-examples)
- [🆘  Getting Help in the Linux Shell](#--getting-help-in-the-linux-shell)
  - [🧠 Why It's Important](#-why-its-important)
  - [🧾 `man` – Manual Pages](#-man--manual-pages)
  - [Prompt recap](#prompt-recap)
- [🧠 System Information (Linux Basics)](#-system-information-linux-basics)
  - [🖥️ Basic System \& User Info](#️-basic-system--user-info)
  - [🌐 Network \& Interface Info](#-network--interface-info)
  - [👥 Users \& Sessions](#-users--sessions)
  - [💽 Devices \& Storage](#-devices--storage)
  - [⚙️ Processes](#️-processes)
  - [🛠️ Pro Tips](#️-pro-tips)
    - [📟 Essential Commands After Login](#-essential-commands-after-login)
    - [🧠 Why It Matters](#-why-it-matters)
- [📂 Linux Navigation - HTB Notes](#-linux-navigation---htb-notes)
  - [🧭 Overview](#-overview)
  - [📍 Current Directory](#-current-directory)
  - [**Find Command in Linux**](#find-command-in-linux)
    - [**Purpose**](#purpose)
    - [**Syntax**](#syntax)
  - [**Find Command Options Explained**](#find-command-options-explained)
    - [**Options and Their Descriptions**](#options-and-their-descriptions)
    - [**Example**](#example)
    - [**Command Breakdown**](#command-breakdown)
  - [**Locate Command in Linux**](#locate-command-in-linux)
    - [**Key Characteristics**](#key-characteristics)
    - [**Update the Database**](#update-the-database)
    - [**Limitations**](#limitations)
    - [**When to Use**](#when-to-use)
- [**File Descriptors and Redirections**](#file-descriptors-and-redirections)
    - [**Analogy**](#analogy)
    - [**Default File Descriptors in Linux**](#default-file-descriptors-in-linux)
    - [**STDIN and STDOUT Example**](#stdin-and-stdout-example)
  - [**STDOUT and STDERR**](#stdout-and-stderr)
    - [**Redirecting STDERR**](#redirecting-stderr)
    - [**Redirecting STDOUT to a File**](#redirecting-stdout-to-a-file)
    - [**Redirecting STDOUT and STDERR to Separate Files**](#redirecting-stdout-and-stderr-to-separate-files)
    - [**Redirecting STDIN**](#redirecting-stdin)
    - [**Appending STDOUT to an Existing File**](#appending-stdout-to-an-existing-file)
    - [**Redirecting STDIN Stream with EOF**](#redirecting-stdin-stream-with-eof)
  - [**Pipes**](#pipes)
    - [**How Pipes Work**](#how-pipes-work)
    - [**Common Usage Example**](#common-usage-example)
    - [**Chaining Multiple Commands**](#chaining-multiple-commands)
    - [**Why It Matters**](#why-it-matters)
  - [**In Summary**](#in-summary)
- [**Filter Contents**](#filter-contents)
  - [**Pagers: `more` and `less`**](#pagers-more-and-less)
    - [**Why Use Pagers?**](#why-use-pagers)
    - [**Before Filtering**](#before-filtering)
    - [**Example Scenario**](#example-scenario)
    - [**Key Takeaway**](#key-takeaway)
  - [**Filtering and Viewing File Contents**](#filtering-and-viewing-file-contents)
    - [**1. Less**](#1-less)
    - [**2. Head**](#2-head)
    - [**3. Tail**](#3-tail)
    - [**4. Sort**](#4-sort)
    - [**5. Grep**](#5-grep)
  - [**Why These Tools Matter**](#why-these-tools-matter)
    - [**Key Takeaways**](#key-takeaways)
- [**Advanced Text Processing and Filtering Tools**](#advanced-text-processing-and-filtering-tools)
    - [**1. Cut**](#1-cut)
    - [**2. Tr (Translate)**](#2-tr-translate)
    - [**3. Column**](#3-column)
    - [**4. Awk**](#4-awk)
    - [**5. Sed (Stream Editor)**](#5-sed-stream-editor)
    - [**6. Wc (Word Count)**](#6-wc-word-count)
    - [**Practice and Exploration**](#practice-and-exploration)
    - [**Key Takeaways**](#key-takeaways-1)
- [Regular Expressions](#regular-expressions)
  - [Grouping](#grouping)
    - [Grouping Operators](#grouping-operators)
- [Permission Management](#permission-management)
  - [Directory Access and Execute Permission](#directory-access-and-execute-permission)
  - [File Permissions Summary](#file-permissions-summary)
  - [Example: File Permission Breakdown](#example-file-permission-breakdown)
- [Modifying Directories](#modifying-directories)
- [Change Permissions](#change-permissions)
  - [Change Owner](#change-owner)
- [SUID \& SGID](#suid--sgid)
    - [Indicators](#indicators)
    - [Risks](#risks)
    - [Sticky Bit](#sticky-bit)
- [User Management](#user-management)
  - [# Execution as a Different User](#-execution-as-a-different-user)
  - [# Essential User Management Commands](#-essential-user-management-commands)
- [Package Management](#package-management)
  - [What Are Packages?](#what-are-packages)
  - [Core Package Management Features](#core-package-management-features)
  - [Common Package Formats](#common-package-formats)
  - [Popular Package Management Tools](#popular-package-management-tools)
  - [Lifecycle of a Package (Simplified)](#lifecycle-of-a-package-simplified)
    - [Best Practices](#best-practices)
- [Advanced Package Management (APT)](#advanced-package-management-apt)
  - [Overview](#overview)
  - [Repositories](#repositories)
  - [APT Cache](#apt-cache)
    - [Common operations:](#common-operations)
  - [Installing Packages via APT](#installing-packages-via-apt)
  - [Git Integration](#git-integration)
  - [DPKG (Low-level package installation)](#dpkg-low-level-package-installation)
  - [Summary Table](#summary-table)
- [Service and Process Management](#service-and-process-management)
  - [Overview](#overview-1)
  - [Naming Convention](#naming-convention)
  - [Common Management Tasks](#common-management-tasks)
  - [Init System: systemd](#init-system-systemd)
- [Tools \& Commands](#tools--commands)
  - [systemctl](#systemctl)
  - [ps](#ps)
  - [journalctl](#journalctl)
  - [Kill Signals](#kill-signals)
  - [Process Control](#process-control)
  - [Process States](#process-states)
  - [Execute Multiple Commands](#execute-multiple-commands)
    - [Examples of Command Flow Behavior](#examples-of-command-flow-behavior)
- [Task Scheduling](#task-scheduling)
  - [Overview](#overview-2)
- [Systemd-Based Scheduling](#systemd-based-scheduling)
  - [Structure](#structure)
  - [Timer Unit Sections](#timer-unit-sections)
  - [Service Unit Sections](#service-unit-sections)
- [Cron-Based Scheduling](#cron-based-scheduling)
  - [Crontab Time Format](#crontab-time-format)
  - [Crontab Notes](#crontab-notes)
  - [Comparison: systemd vs cron](#comparison-systemd-vs-cron)
  - [Why It Matters in Cybersecurity](#why-it-matters-in-cybersecurity)
- [Network Services](#network-services)
  - [Why It Matters](#why-it-matters-1)
  - [SSH (Secure Shell)](#ssh-secure-shell)
  - [NFS (Network File System)](#nfs-network-file-system)
  - [Web Server](#web-server)
  - [Python Web Server](#python-web-server)
  - [VPN (Virtual Private Network)](#vpn-virtual-private-network)
  - [Summary Table](#summary-table-1)
  - [Security Insights](#security-insights)
- [Methodology: Network Services (Enumeration \& Exploitation)](#methodology-network-services-enumeration--exploitation)
  - [🔐 SSH (Secure Shell)](#-ssh-secure-shell)
    - [Enumeration](#enumeration)
    - [Exploitation Opportunities](#exploitation-opportunities)
  - [📁 NFS (Network File System)](#-nfs-network-file-system)
    - [Enumeration](#enumeration-1)
    - [Exploitation Opportunities](#exploitation-opportunities-1)
  - [🌐 Web Servers (Apache, Python HTTP, etc.)](#-web-servers-apache-python-http-etc)
    - [Enumeration](#enumeration-2)
    - [Exploitation Opportunities](#exploitation-opportunities-2)
  - [🐍 Python Web Server](#-python-web-server)
    - [Use Cases](#use-cases)
  - [🌍 VPN (OpenVPN)](#-vpn-openvpn)
    - [Enumeration](#enumeration-3)
    - [Exploitation Opportunities](#exploitation-opportunities-3)
  - [🧠 General Tips](#-general-tips)
- [Working with Web Services](#working-with-web-services)
  - [🔧 Web Servers Overview](#-web-servers-overview)
  - [🏗 Apache Web Server](#-apache-web-server)
    - [Common Modules](#common-modules)
  - [🌐 Port Configuration](#-port-configuration)
  - [🌍 Testing the Web Server](#-testing-the-web-server)
  - [🧰 CLI Tools for Web Interaction](#-cli-tools-for-web-interaction)
    - [curl](#curl)
    - [wget](#wget)
  - [🐍 Python HTTP Server](#-python-http-server)
  - [🛠 Tools Comparison](#-tools-comparison)
  - [💭 Pentesting \& Real-World Relevance](#-pentesting--real-world-relevance)
- [Backup and Restore](#backup-and-restore)
  - [🧱 Backup Tools on Linux](#-backup-tools-on-linux)
  - [🔁 rsync Key Concepts](#-rsync-key-concepts)
    - [Common Flags](#common-flags)
  - [📥 Local Backup Example](#-local-backup-example)
  - [🔐 Encrypted Transfers](#-encrypted-transfers)
  - [🔄 Restore with rsync](#-restore-with-rsync)
  - [🧠 Auto-Sync with Cron](#-auto-sync-with-cron)
    - [Cron Entry Format](#cron-entry-format)
- [Containerization](#containerization)
  - [Overview](#overview-3)
  - [Advantages](#advantages)
  - [Docker](#docker)
    - [What is Docker?](#what-is-docker)
    - [Analogy](#analogy-1)
    - [Docker Workflow](#docker-workflow)
    - [Key Docker Concepts](#key-docker-concepts)
    - [Useful Docker Commands](#useful-docker-commands)
    - [Persistence \& State](#persistence--state)
  - [LXC (Linux Containers)](#lxc-linux-containers)
    - [What is LXC?](#what-is-lxc)
    - [LXC vs Docker](#lxc-vs-docker)
    - [LXC Core Tools](#lxc-core-tools)
    - [Isolation with Namespaces](#isolation-with-namespaces)
    - [Resource Limits (Cgroups)](#resource-limits-cgroups)
    - [Security Tips](#security-tips)
  - [Container Use Cases in Pentesting](#container-use-cases-in-pentesting)
  - [Practice Exercises](#practice-exercises)
- [Network Configuration](#network-configuration)
  - [🌐 Interface Configuration](#-interface-configuration)
  - [🔐 Network Access Control (NAC)](#-network-access-control-nac)
  - [🧰 Troubleshooting Tools](#-troubleshooting-tools)
  - [🛡️ Hardening Tools](#️-hardening-tools)
  - [🧠 Tips](#-tips)
- [Linux Security](#linux-security)
  - [🔒 System Hardening Basics](#-system-hardening-basics)
  - [🔍 Regular System Auditing](#-regular-system-auditing)
  - [🛡️ Access Control Mechanisms](#️-access-control-mechanisms)
  - [🗂️ General Security Practices](#️-general-security-practices)
- [TCP Wrappers](#tcp-wrappers)
    - [🟩 Example `/etc/hosts.allow`](#-example-etchostsallow)
    - [🟥 Example `/etc/hosts.deny`](#-example-etchostsdeny)
- [🔥 Firewall Setup](#-firewall-setup)
  - [🎯 Purpose](#-purpose)
  - [🛡️ Evolution](#️-evolution)
  - [🔧 iptables Components](#-iptables-components)
  - [📋 Tables Overview](#-tables-overview)
  - [🧱 Built-in Chains (Examples)](#-built-in-chains-examples)
  - [🎯 Targets](#-targets)
  - [🎯 Matches](#-matches)
  - [⚙️ Example Rule](#️-example-rule)
  - [🧪 Practical Checklist](#-practical-checklist)
- [📄 System Logs](#-system-logs)
  - [🔒 Logging Best Practices](#-logging-best-practices)
  - [🧩 Types of Logs](#-types-of-logs)
  - [🧠 Kernel Logs](#-kernel-logs)
  - [🖥️ System Logs](#️-system-logs)
  - [🔑 Authentication Logs](#-authentication-logs)
  - [📦 Application Logs](#-application-logs)
  - [🛡️ Security Logs](#️-security-logs)
  - [🧰 Useful Commands](#-useful-commands)
---


for cheat sheet on Commands check:  [[Linux_Fundamentals_Module_Cheat_Sheet.pdf]]

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

| Operator   | Description                                                                  |
|------------|------------------------------------------------------------------------------|
| `(a)`      | Round brackets are used to group parts of a regex pattern for joint matching |
| `[a-z]`    | Square brackets define a character class — match any one of the listed chars |
| `{1,10}`   | Curly brackets define quantifiers — how many times the pattern should repeat |
| `|`        | OR operator — matches if **either** of the expressions is present            |
| `.*`       | AND-like chaining — matches if **both** patterns exist in the given order    |

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

# User Management

Effective user management is essential in Linux administration. Admins must create users, assign them to groups, and control permissions to maintain system security and resource access.

## # Execution as a Different User

- **`sudo`** allows permitted users to run commands with elevated privileges (usually as `root`).
- **`su`** switches to another user account (default: root) after verifying credentials.

> 🔒 Files like `/etc/shadow` (stores encrypted passwords) are only readable by `root`.

## # Essential User Management Commands

| Command     | Description                                                  |
|-------------|--------------------------------------------------------------|
| `sudo`      | Run a command as another user (commonly as root).            |
| `su`        | Switch to another user (with login shell).                   |
| `useradd`   | Create a new user.                                           |
| `userdel`   | Delete a user and optionally their files.                    |
| `usermod`   | Modify a user's account settings.                            |
| `addgroup`  | Add a new group to the system.                               |
| `delgroup`  | Delete a group from the system.                              |
| `passwd`    | Change a user's password.                                    |

---

# Package Management

Understanding package management is essential for installing, upgrading, and removing software on Linux systems. This knowledge is crucial whether you're managing personal machines, administering servers, or customizing penetration testing environments.

## What Are Packages?

Packages are archive files that contain:
- Compiled software binaries  
- Configuration files  
- Metadata (like version and dependencies)

They provide a consistent, manageable way to:
- Distribute applications
- Keep track of versions and updates
- Resolve and install dependencies

---

## Core Package Management Features

- **Download & install packages**
- **Resolve dependencies automatically**
- **Use standardized formats** (`.deb`, `.rpm`, etc.)
- **Enforce quality & system integration**
- **Track updates and removals**

---

## Common Package Formats

| Format | Description                        |
|--------|------------------------------------|
| `.deb` | Debian-based systems (Ubuntu, Kali) |
| `.rpm` | RedHat-based systems (Fedora, CentOS) |

---

## Popular Package Management Tools

| Command   | Description |
|-----------|-------------|
| **dpkg**  | Core tool for `.deb` packages (low-level) |
| **apt**   | High-level interface for package management in Debian-based systems |
| **aptitude** | Alternative to apt with ncurses interface and smarter resolution |
| **snap**  | Package manager for sandboxed apps (used in modern Ubuntu systems) |
| **gem**   | Ruby package manager |
| **pip**   | Python package installer |
| **git**   | Version control tool, often used to clone and build packages manually |

---

## Lifecycle of a Package (Simplified)

1. **Install**  
   Downloads the package and its dependencies from a repo → installs all of them

2. **Upgrade**  
   Replaces the package with a newer version, resolves any new dependencies

3. **Remove**  
   Deletes the package and optionally its configs, may leave dependencies behind

4. **Purge**  
   Removes *everything*, including config files

### Best Practices

- Always `update` before `upgrade` (`apt update && apt upgrade`)
- Use `apt install` over `dpkg -i` for better dependency handling
- Clean up unused packages with `apt autoremove`
- Use virtual environments for Python (`venv`) or Ruby (`rvm`) when testing packages
- Never install random `.deb` files from the internet without verifying the source

---

# Advanced Package Management (APT)

## Overview
- APT is the package manager used by Debian-based distros like Kali and Parrot.
- It simplifies installing and updating programs, resolving dependencies automatically.
- Under the hood, it uses `dpkg`, which works with `.deb` files directly.
- APT avoids manual dependency management by fetching all required packages.

---

## Repositories
- Software is fetched from online repositories categorized as:
  - Stable
  - Testing
  - Unstable
- Most systems use the "main" stable repo.
- Repository configuration is found at:
  - `/etc/apt/sources.list`
  - `/etc/apt/sources.list.d/parrot.list` (in Parrot OS)

---

## APT Cache
- APT maintains an offline cache with metadata about available packages.
- This allows searching and inspecting packages without needing an internet connection.

### Common operations:
- Search the cache for packages
- Show detailed metadata (version, dependencies, maintainer)
- List installed packages on the system

---

## Installing Packages via APT
- Automatically handles downloads, installs, and dependencies.
- Fetches from configured repositories.
- Example use case: installing penetration testing tools like `impacket-scripts`.

---

## Git Integration
- Git is often used to download tools and projects from GitHub.
- It's common to create dedicated folders for tools (e.g., `~/nishang`) and clone repositories into them.
- Git provides full version control and local access to scripts and exploits.

---

## DPKG (Low-level package installation)
- Used to manually install `.deb` packages when downloading them directly.
- Does not handle dependencies; manual resolution may be needed.
- Useful when installing tools from archived mirrors or offline sources.

---

## Summary Table

| Tool       | Role                                      | Handles Dependencies | Works Offline | Notes                             |
|------------|-------------------------------------------|----------------------|---------------|------------------------------------|
| APT        | High-level package manager                | ✅                   | ✅ (cache)     | Uses repos, resolves dependencies |
| dpkg       | Low-level package installer for .deb      | ❌                   | ✅             | No dependency resolution          |
| Git        | Source control + download from GitHub     | ❌                   | ✅             | Used for scripts, not packages    |

---

# Service and Process Management

## Overview
- Services (daemons) are background programs running without direct user interaction.
- Two main categories:
  - **System Services**: Core OS components, run at startup.
  - **User-Installed Services**: Installed by the user, add functionality.

---

## Naming Convention
- Daemons usually end in `d`, e.g.:
  - `sshd`: SSH daemon
  - `systemd`: Init and service manager

---

## Common Management Tasks

| Goal                             | Description                                    |
|----------------------------------|------------------------------------------------|
| Start/Restart a service/process | Make a service or process begin operation     |
| Stop a service/process           | Halt the service or process                   |
| Check status                     | View current state and logs                   |
| Enable/Disable on boot           | Control automatic start during boot           |
| Find a service/process           | Locate running background tasks               |

---

## Init System: systemd
- Most modern distros use `systemd`
- First process that runs at boot
- Assigned **PID 1**
- All Linux processes have a **PID** and may have a **PPID** (parent)

---

# Tools & Commands

## systemctl
- Manage services (start, stop, status, enable, disable)
- List all services on the system

## ps
- List active processes
- Can be filtered using pipes or grep

## journalctl
- View detailed logs from systemd-managed services
- Helps in debugging service failures

---

## Kill Signals

| Signal   | Description                                  |
|----------|----------------------------------------------|
| SIGHUP   | Terminal closed                              |
| SIGINT   | Ctrl+C                                       |
| SIGQUIT  | Ctrl+D                                       |
| SIGKILL  | Force kill                                   |
| SIGTERM  | Terminate gracefully                         |
| SIGSTOP  | Hard stop (cannot be handled)                |
| SIGTSTP  | Ctrl+Z (suspend, can resume with bg/fg)      |

---

## Process Control

| Task                    | Description                                                |
|-------------------------|------------------------------------------------------------|
| Send signal to process  | Use `kill`, `pkill`, `killall`                             |
| List running jobs       | Use `jobs` to see suspended/background processes           |
| Background a process    | Use `Ctrl+Z` to suspend, then `bg` to run in background    |
| Foreground a process    | Use `fg <ID>` to resume interaction                        |
| Run in background       | Append `&` to command                                      |

---

## Process States

- **Running**: Actively executing
- **Waiting**: Awaiting resource or event
- **Stopped**: Suspended by signal
- **Zombie**: Completed but not removed from process table

---

## Execute Multiple Commands

| Separator | Behavior                                                                    |
|-----------|-----------------------------------------------------------------------------|
| `;`       | Run all commands regardless of success/failure                              |
| `&&`      | Run next command **only if previous succeeded**                             |
| `|`       | Pipe output of one command to the input of the next                         |

---

### Examples of Command Flow Behavior

| Sequence Type | Continues After Error? | Dependent on Output? |
|---------------|------------------------|-----------------------|
| `;`           | ✅ Yes                 | ❌ No                |
| `&&`          | ❌ No                  | ❌ No                |
| `|`           | ✅ Yes (usually)       | ✅ Yes              |

---

# Task Scheduling

## Overview
- Automates repetitive or time-based tasks.
- Common use cases:
  - Software updates
  - Scripted scans
  - DB maintenance
  - Log rotation / backups
  - Malicious persistence techniques

---

# Systemd-Based Scheduling

## Structure

| Component      | Description                                               |
|----------------|-----------------------------------------------------------|
| Timer Unit     | Defines *when* the task should run                        |
| Service Unit   | Defines *what* the task actually does (executes script)   |
| Activation     | Timer must be started and enabled to persist across reboots |

## Timer Unit Sections

- **[Unit]**: Description of the timer
- **[Timer]**: Defines timing (e.g. `OnBootSec=`, `OnUnitActiveSec=`)
- **[Install]**: Enables the timer on boot (`WantedBy=timers.target`)

## Service Unit Sections

- **[Unit]**: Description of the service
- **[Service]**: Contains `ExecStart=` with the full script path
- **[Install]**: Ensures the service starts in correct target (`multi-user.target`)

---

# Cron-Based Scheduling

## Crontab Time Format

| Field            | Values       | Description                         |
|------------------|--------------|-------------------------------------|
| Minute           | 0-59         | When during the hour                |
| Hour             | 0-23         | Which hour                          |
| Day of Month     | 1-31         | Which day of the month              |
| Month            | 1-12         | Which month                         |
| Day of Week      | 0-7 (0,7=Sun)| Which day of the week               |

## Crontab Notes

- Tasks are written as:  
  `MIN HOUR DOM MON DOW /full/path/to/script.sh`
- Can automate system updates, backups, cleanup, etc.
- Can log task output or send notifications.

---

## Comparison: systemd vs cron

| Feature            | systemd                                 | cron                             |
|--------------------|------------------------------------------|----------------------------------|
| Granularity        | High (events, delays, time)              | Time-based only                  |
| Logging            | Native via `journalctl`                  | Manual (needs redirection)       |
| Service handling   | Native support with units                | Limited                          |
| Syntax complexity  | Higher (multiple files/sections)         | Lower (one-line entries)         |
| Boot-awareness     | Supports boot triggers (`OnBootSec`)     | Doesn't natively support it      |
| Best for           | Modern automation, complex tasks         | Simple recurring jobs            |

---

## Why It Matters in Cybersecurity

- **Defensive**: Automate monitoring, updates, backups, auditing.
- **Offensive**: Abuse task schedulers for persistence, backdoors, data exfil.
- **Detection**: Spot unauthorized timers or cron entries as part of forensic analysis.

---

# Network Services

## Why It Matters
- Enables remote access, file transfer, service interaction, and system administration.
- Misconfigured services can expose credentials, sensitive data, or access points.
- Crucial for both sysadmins and penetration testers to understand and manipulate securely.

---

## SSH (Secure Shell)

- Provides encrypted remote access to Linux systems.
- Most common implementation: **OpenSSH**
- Use cases:
  - Remote shell access
  - Secure file transfer
  - Tunneling / port forwarding
- Configuration file: `/etc/ssh/sshd_config`
- Supports authentication via password or key pair.

---

## NFS (Network File System)

- Allows file sharing over the network as if local.
- Common in shared environments or centralized storage systems.
- Configuration file: `/etc/exports`
- Permissions:

| Option          | Description                                             |
|-----------------|---------------------------------------------------------|
| `rw`            | Read/Write access                                       |
| `ro`            | Read-only access                                        |
| `root_squash`   | Limits client root to non-root privileges               |
| `no_root_squash`| Grants full root access to client root                  |
| `sync`          | Data written only after being committed                 |
| `async`         | Faster, but less safe (possible inconsistencies)        |

- Requires mounting from client systems to access.

---

## Web Server

- Serves HTML, files, APIs over HTTP/HTTPS.
- Key web server options:
  - **Apache2** (default on many distros)
  - **Nginx**
  - **Lighttpd**
  - **Python SimpleHTTPServer**
- Apache config file: `/etc/apache2/apache2.conf`
- Directory-specific config: `.htaccess`
- Use cases:
  - File hosting
  - Web apps
  - Phishing payloads or reverse shell delivery
- Log configuration is important for forensics and threat detection.

---

## Python Web Server

- Lightweight, fast file server for quick transfers.
- Useful for quick testing or payload delivery during assessments.
- Default port: 8000 (can be changed)

---

## VPN (Virtual Private Network)

- Encrypted tunnel for accessing remote/internal networks.
- Common solutions:
  - **OpenVPN**
  - L2TP/IPsec
  - SSTP
  - SoftEther
- Admins use it for remote access and secure traffic.
- Pentesters use it to reach internal resources during engagements.
- OpenVPN config: `/etc/openvpn/server.conf`
- Requires `.ovpn` file to connect as client.

---

## Summary Table

| Service     | Role                                      | Config File                        | Key Use Case                      |
|-------------|-------------------------------------------|------------------------------------|-----------------------------------|
| SSH         | Remote shell access, tunneling            | `/etc/ssh/sshd_config`             | Secure system management          |
| NFS         | File sharing across hosts                 | `/etc/exports`                     | Remote access to shared data      |
| Apache2     | Full-featured web hosting                 | `/etc/apache2/apache2.conf`        | Serve websites, payloads, tools   |
| Python HTTP | Lightweight web file server               | N/A                                | Quick payload delivery            |
| OpenVPN     | Secure network tunnel                     | `/etc/openvpn/server.conf`         | Remote access / pivoting          |

---

## Security Insights

- SSH brute-force attacks are common — disable password auth if possible.
- NFS shares can be abused for privilege escalation or lateral movement.
- Web servers are high-value targets — XSS, LFI, RCE are common threats.
- Misconfigured VPNs can expose internal networks externally.

---

# Methodology: Network Services (Enumeration & Exploitation)


## 🔐 SSH (Secure Shell)

### Enumeration
- Identify port (usually 22) via Nmap.
- Check banner/version: `nmap -sV -p 22 <target>`
- Test login with common creds or bruteforce (Hydra, Medusa).
- Inspect `sshd_config` if readable (misconfigured permissions).

### Exploitation Opportunities
- Weak credentials
- Key-based auth leaks (e.g. exposed `id_rsa`)
- Command injection via restricted shells (e.g. git-shell, rbash)
- Port forwarding/tunneling (pivoting)

---

## 📁 NFS (Network File System)

### Enumeration
- Port usually 2049 (check with Nmap)
- List exports: `showmount -e <target>`
- Mount exported directory: `mount <target>:/exported/path /mnt/target_nfs`

### Exploitation Opportunities
- `no_root_squash` allows root to write files with UID 0
- Upload SUID binaries or SSH keys to authorized_keys
- Access sensitive files due to misconfigured share paths

---

## 🌐 Web Servers (Apache, Python HTTP, etc.)

### Enumeration
- Identify open HTTP/HTTPS ports (80, 443, 8080, etc)
- Crawl site and analyze: `gobuster`, `dirsearch`, `whatweb`, `nikto`
- Check headers, robots.txt, and file uploads

### Exploitation Opportunities
- LFI/RFI vulnerabilities
- File upload abuse
- Default credentials on web panels
- XSS, SQLi, Command Injection

---

## 🐍 Python Web Server

### Use Cases
- Fast file transfers during engagements
- Drop malicious scripts or reverse shells
- Test client interaction via hosted payloads

---

## 🌍 VPN (OpenVPN)

### Enumeration
- Look for .ovpn config files on target
- Identify VPN interfaces via `ifconfig` / `ip a`
- Monitor routes: `route -n`, `ip route`

### Exploitation Opportunities
- Misconfigured routing allows lateral movement
- VPN split-tunneling risks
- VPN client leaks sensitive internal resources

---

## 🧠 General Tips

- Use `systemctl status <service>` or `ps aux` to validate what’s running.
- Log all service configuration files when you have read access.
- Look for creds/tokens inside config files (e.g. `/etc/apache2`, `/etc/ssh`)
- Pivot through services to internal networks using SSH tunnels or VPN

---

# Working with Web Services

## 🔧 Web Servers Overview

- Web servers serve static and dynamic content over HTTP/HTTPS.
- Commonly used servers:
  - **Apache2** (modular, widely used)
  - **Nginx**
  - **Python HTTP Server** (lightweight, fast testing)
- Configuration involves setting ports, modules, and accessible directories.

---

## 🏗 Apache Web Server

- Acts as the "engine" behind web communication.
- Fully modular (e.g. `mod_ssl`, `mod_proxy`, `mod_rewrite`, `mod_headers`)
- Supports dynamic content via PHP, Perl, Ruby, Python, etc.
- Default config file: `/etc/apache2/apache2.conf`
- Default web root: `/var/www/html`

### Common Modules

| Module        | Purpose                                             |
|---------------|-----------------------------------------------------|
| `mod_ssl`     | Enables HTTPS (TLS encryption)                      |
| `mod_proxy`   | Handles reverse proxying and load balancing         |
| `mod_headers` | Manages custom headers and policies                 |
| `mod_rewrite` | URL rewriting and redirection                       |

---

## 🌐 Port Configuration

- Apache listens on port **80** by default.
- To change, edit: `/etc/apache2/ports.conf`
- Also update: `/etc/apache2/sites-enabled/000-default.conf`
- Common alternate port: **8080**

---

## 🌍 Testing the Web Server

- Verify with `http://localhost` or `curl http://localhost`
- Default page: “It works!” confirms successful setup

---

## 🧰 CLI Tools for Web Interaction

### curl

- Used to send HTTP/HTTPS requests and receive raw HTML
- Prints output to terminal (STDOUT)
- Good for:
  - Verifying server response
  - Inspecting headers
  - Automation via scripts

### wget

- Downloads files or web pages from HTTP, HTTPS, or FTP
- Stores content to local file
- Great for:
  - Fetching files
  - Web scraping
  - Offline copies

---

## 🐍 Python HTTP Server

- Lightweight local server, great for file transfers
- Usage starts at current directory
- Default port: **8000**
- Supports:
  - Hosting payloads or exploits
  - Serving HTML locally
  - Directory listings

---

## 🛠 Tools Comparison

| Tool/Service     | Role                        | Output Type   | Default Port | Best For                              |
|------------------|-----------------------------|----------------|---------------|----------------------------------------|
| Apache2          | Full web server              | Rendered HTML | 80 / 443     | Hosting static/dynamic websites       |
| Python Server    | Lightweight web server       | File index    | 8000         | Quick local hosting                    |
| curl             | HTTP request tool            | Terminal text | N/A          | Fetching response body/headers        |
| wget             | HTTP download tool           | Local file    | N/A          | Downloading resources/files           |

---

## 💭 Pentesting & Real-World Relevance

- Understanding web services allows:
  - Local server hosting for

---

# Backup and Restore

## 🧱 Backup Tools on Linux

| Tool        | Purpose                          | CLI or GUI | Supports Encryption | Notes                           |
|-------------|----------------------------------|------------|----------------------|----------------------------------|
| rsync       | Efficient local/remote sync      | CLI        | Via SSH              | Incremental + compression       |
| duplicity   | Secure remote backups            | CLI        | ✅ Yes               | Uses rsync + GPG encryption     |
| deja-dup    | Simple GUI for backups           | GUI        | ✅ Yes               | Built on duplicity              |

---

## 🔁 rsync Key Concepts

- Only syncs changed blocks → highly efficient
- Preserves permissions, ownership, timestamps
- Can use SSH for encrypted transfer
- Supports compression, deletion, backup directories

### Common Flags

| Flag      | Purpose                                 |
|-----------|------------------------------------------|
| `-a`      | Archive mode (preserves file properties) |
| `-v`      | Verbose output                           |
| `-z`      | Compress file data during the transfer   |
| `--delete`| Delete files at destination not in source|
| `--backup`| Create backups of overwritten files      |
| `--backup-dir=`| Location to store backup copies     |
| `-e ssh`  | Use SSH for secure data transfer         |

---

## 📥 Local Backup Example

- Sync directory locally:
  - Source: `/path/to/mydirectory`
  - Destination: `/backup_server:/path/to/backup/directory`

---

## 🔐 Encrypted Transfers

- Use SSH in rsync with `-e ssh`
- Encrypts data in transit
- Enhances confidentiality and integrity
- Combine with firewalls and key-based auth for strong protection

---

## 🔄 Restore with rsync

- Inverse direction:
  - From backup server → to local directory
  - Same options, just flip source and destination

---

## 🧠 Auto-Sync with Cron

1. Create an `rsync` script (e.g., `RSYNC_Backup.sh`)
2. Add execute permission: `chmod +x`
3. Set up SSH key-based auth with `ssh-keygen` and `ssh-copy-id`
4. Add cron job:

### Cron Entry Format

| Field       | Meaning                  |
|-------------|---------------------------|
| `0 * * * *` | Run every hour on the hour|

---

# Containerization

## Overview
- Containerization: Running apps in isolated, lightweight environments.
- Tools: Docker, Docker Compose, LXC.
- Shares host OS kernel, unlike VMs.

## Advantages
- Portability
- Lightweight
- Isolation
- Security

## Docker

### What is Docker?
- App-focused containerization platform.
- Uses layered images.
- Popular for reproducibility & CI/CD.

### Analogy
Docker container = sealed lunchbox. Portable, disposable, consistent.

### Docker Workflow
- Build image from Dockerfile.
- Run container from image.
- Use Docker Hub for prebuilt images or sharing.

### Key Docker Concepts
- Dockerfile: recipe to build images.
- Image: read-only template.
- Container: running instance of image.
- Port mapping, volumes, environment variables for customization.

### Useful Docker Commands
- `docker ps` — List running containers.
- `docker stop/start/restart <id>` — Manage containers.
- `docker rm <id>` — Remove container.
- `docker rmi <image>` — Remove image.
- `docker logs <id>` — View logs.

### Persistence & State
- Containers are stateless by default.
- Use volumes or rebuild images for persistent state.
- Use `docker build -t <tag> .` to rebuild new image from Dockerfile.

## LXC (Linux Containers)

### What is LXC?
- System-level containerization using cgroups & namespaces.
- More "VM-like" than Docker but lighter than full virtualization.

### LXC vs Docker

| Category       | Docker                                | LXC                                    |
|----------------|----------------------------------------|-----------------------------------------|
| Approach       | Application-focused                    | System-level containerization           |
| Image Format   | Dockerfile-based                       | Manual setup                            |
| Portability    | High (Docker Hub, registries)          | Low                                     |
| Ease of Use    | Beginner-friendly CLI, DevOps ready    | Requires Linux sysadmin skills          |
| Security       | AppArmor, SELinux, RO FS               | Needs manual hardening                  |

### LXC Core Tools
- `lxc-create` — Create container.
- `lxc-start/stop/restart` — Control container state.
- `lxc-attach` — Enter container shell.
- `lxc-ls` — List containers.

### Isolation with Namespaces
- PID (process)
- NET (network interfaces)
- MNT (filesystem)
- IPC (interprocess comms)
- UTS (hostname/domain)
- USER (user/group IDs)

### Resource Limits (Cgroups)
- `lxc.cgroup.cpu.shares = 512`
- `lxc.cgroup.memory.limit_in_bytes = 512M`

### Security Tips
- Restrict SSH or allowlist IPs.
- Limit CPU/mem usage.
- Patch containers & base OS.
- Harden container config.
- Disable unnecessary services.

## Container Use Cases in Pentesting
- File hosting (HTTP/SSH).
- Simulating vulnerable environments.
- Controlled malware/exploit testing.
- Reproducing target environments.
- Running attack tools in isolated space.

## Practice Exercises
1. Install LXC and create a container.
2. Configure networking for LXC.
3. Build custom LXC image.
4. Apply CPU/memory/disk quotas.
5. Use LXC to host a service.
6. Enable SSH into LXC.
7. Test persistence.
8. Simulate vulnerable app in container.
9. Practice exploit dev safely in isolated space.

---

# Network Configuration

## 🌐 Interface Configuration
| Tool     | Purpose                                      |
|----------|----------------------------------------------|
| `ifconfig` | View/assign IP, netmask (deprecated)       |
| `ip`       | Modern tool to manage interfaces, routes   |

- Activate interface: `ifconfig eth0 up` / `ip link set eth0 up`
- Assign IP: `ifconfig eth0 192.168.1.2`
- Set netmask: `ifconfig eth0 netmask 255.255.255.0`
- Add gateway: `route add default gw 192.168.1.1 eth0`
- Edit DNS:
  - Temporary: `/etc/resolv.conf`
  - Persistent: via `/etc/network/interfaces` or NM/systemd-resolved
- Make config persistent:

**`/etc/network/interfaces`**
**`auto eth0`**
**`iface eth0 inet static`**
**`address 192.168.1.2`**
**`netmask 255.255.255.0`**
**`gateway 192.168.1.1`**
**`dns-nameservers 8.8.8.8 8.8.4.4`**

## 🔐 Network Access Control (NAC)
| Model | Description |
|-------|-------------|
| DAC   | Owner sets permissions (e.g. `chmod`) |
| MAC   | OS-enforced; label-based (e.g. SELinux) |
| RBAC  | Role-based; user roles define access |

- SELinux → label-based, kernel-enforced (strict)
- AppArmor → profile-based, simpler
- TCP Wrappers → allow/deny based on IP (`/etc/hosts.allow`, `/etc/hosts.deny`)

## 🧰 Troubleshooting Tools
| Tool        | Use                          |
|-------------|-------------------------------|
| ping        | Reachability (ICMP echo)      |
| traceroute  | Trace network path            |
| netstat -a  | List all open connections     |
| tcpdump     | Packet capture (CLI)          |
| wireshark   | GUI packet analyzer           |
| nmap        | Port scanning / enumeration   |

## 🛡️ Hardening Tools
| Tool         | Type | Details |
|--------------|------|---------|
| SELinux      | MAC  | High security, complex to manage |
| AppArmor     | MAC  | Easier profiles, simpler usage  |
| TCP Wrappers | NAC  | IP-based access control         |

## 🧠 Tips
- Prefer `ip` over `ifconfig` (modern toolchain)
- Changes to `/etc/resolv.conf` may be overwritten — use NM or systemd for persistent DNS
- Restart networking: `systemctl restart networking`
- Use `ip addr`, `ip link`, `ip route` for modern interface/network info

---

# Linux Security

## 🔒 System Hardening Basics
- **Keep system and packages updated**  
  `apt update && apt dist-upgrade`
- **Configure firewall/iptables** to restrict inbound and outbound traffic
- **Harden SSH access**:
  - Disable password authentication
  - Disable root login
  - Use key-based authentication only
- **Avoid using root directly** — assign minimal sudo rights via `/etc/sudoers`
- **Enable fail2ban**: bans IPs after failed login attempts

---

## 🔍 Regular System Auditing
- Check for:
  - Outdated kernel versions
  - User permission misconfigurations
  - World-writable files
  - Misconfigured cron jobs and services
  - Dangerous SUID/SGID binaries

**Recommended tools**:
- `chkrootkit`
- `rkhunter`
- `Lynis`
- `Snort`

---

## 🛡️ Access Control Mechanisms

| Tool       | Functionality                                                                 |
|------------|--------------------------------------------------------------------------------|
| **SELinux** | Kernel-level Mandatory Access Control (MAC) using labels and policies         |
| **AppArmor**| Profile-based MAC, easier to configure than SELinux                           |
| **sudoers** | Fine-grained command access for users                                         |
| **PAM**     | Pluggable Authentication Modules (e.g., password aging, lockout policies)     |

---

## 🗂️ General Security Practices
- Remove or disable unnecessary services/software
- Eliminate services using unencrypted authentication
- Enable NTP and ensure syslog is running
- Assign **individual user accounts**
- Enforce **strong password policies**
- Use **password aging** and prevent reuse
- Lock accounts after repeated login failures
- Disable unnecessary SUID/SGID binaries

> 🔁 Security is a **process**, not a product. Admin knowledge and vigilance are key.

---

# TCP Wrappers

TCP Wrappers restrict access to services based on IP or hostname. They operate using two files:

- `/etc/hosts.allow`
- `/etc/hosts.deny`

Rules in these files determine whether a client is allowed or denied access to a service.

### 🟩 Example `/etc/hosts.allow`
```
sshd : 10.129.14.0/24
ftpd : 10.129.14.10
telnetd : .inlanefreight.local
```

### 🟥 Example `/etc/hosts.deny`
```
ALL : .inlanefreight.com
sshd : 10.129.22.22
ftpd : 10.129.22.0/24
```

- The **first matching rule** is applied.
- TCP Wrappers **do not replace firewalls** — they only control access to services, not ports.

---

# 🔥 Firewall Setup

## 🎯 Purpose
Firewalls are used to:
- Control & monitor network traffic
- Protect against unauthorized access & malicious activity
- Filter based on IPs, ports, protocols, etc.

---

## 🛡️ Evolution

| Tool       | Description                                                              |
|------------|--------------------------------------------------------------------------|
| `iptables` | CLI tool introduced in Linux 2.4 kernel — filters/modifies packets       |
| `nftables` | Modern replacement of iptables — better syntax, performance              |
| `ufw`      | "Uncomplicated Firewall" — user-friendly interface over iptables         |
| `firewalld`| Dynamic firewall using zones & services for easier management            |

---

## 🔧 iptables Components

| Component | Description                                                                  |
|-----------|------------------------------------------------------------------------------|
| Tables    | Categories of rules based on traffic type (e.g., filter, nat, mangle)         |
| Chains    | Group of rules applied to a type of traffic (INPUT, OUTPUT, FORWARD, etc.)   |
| Rules     | Define match conditions and action (ACCEPT, DROP, etc.)                      |
| Matches   | Conditions like port, protocol, IP, etc. to match traffic                   |
| Targets   | Action to perform if a rule matches (e.g. ACCEPT, DROP, LOG, etc.)           |

---

## 📋 Tables Overview

| Table     | Purpose                                         | Chains                                 |
|-----------|--------------------------------------------------|----------------------------------------|
| `filter`  | Main firewalling — accept/drop traffic           | INPUT, OUTPUT, FORWARD                 |
| `nat`     | NAT translation (src/dst IP changes)             | PREROUTING, POSTROUTING                |
| `mangle`  | Modify packet headers                            | PREROUTING, OUTPUT, INPUT, FORWARD     |
| `raw`     | Exempt from connection tracking                  | PREROUTING, OUTPUT                     |

---

## 🧱 Built-in Chains (Examples)

| Chain        | Purpose                                                                 |
|--------------|-------------------------------------------------------------------------|
| INPUT        | Incoming packets destined for the system                                |
| OUTPUT       | Outbound packets generated by the system                                |
| FORWARD      | Packets routed through the system                                       |
| PREROUTING   | Modify packets before routing decision                                  |
| POSTROUTING  | Modify packets after routing decision                                   |

---

## 🎯 Targets

| Target        | Description                                      |
|---------------|--------------------------------------------------|
| ACCEPT        | Allow the packet                                 |
| DROP          | Silently drop the packet                         |
| REJECT        | Drop + notify sender                             |
| LOG           | Log packet to syslog                             |
| SNAT          | Source NAT                                       |
| DNAT          | Destination NAT                                  |
| MASQUERADE    | Dynamic IP NAT                                   |
| REDIRECT      | Redirect to another port                         |
| MARK          | Tag packet (e.g. for routing decisions)          |

---

## 🎯 Matches

| Match            | Description                                     |
|------------------|-------------------------------------------------|
| `-p`             | Protocol (e.g. tcp, udp, icmp)                   |
| `--dport`        | Destination port                                 |
| `--sport`        | Source port                                      |
| `-s`             | Source IP                                        |
| `-d`             | Destination IP                                   |
| `-m state`       | Match connection state (NEW, ESTABLISHED, etc)  |
| `-m multiport`   | Match multiple ports                             |
| `-m string`      | Match payload string                             |
| `-m mac`         | Match MAC address                                |
| `-m mark`        | Match Netfilter mark                             |
| `-m limit`       | Rate limiting                                    |
| `-m conntrack`   | Connection tracking                              |
| `-m iprange`     | Match IP range                                   |

---

## ⚙️ Example Rule

Allow SSH:
`sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT`

Allow HTTP:
`sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT`

---

## 🧪 Practical Checklist

- Launch web server on port 8080  
- Block incoming traffic on TCP/8080  
- Allow incoming traffic on TCP/8080  
- Block traffic from specific IP  
- Allow traffic from specific IP  
- Block traffic based on protocol  
- Allow traffic based on protocol  
- Create a new chain  
- Forward traffic to custom chain  
- Delete a specific rule  
- List all existing rules:  
  `sudo iptables -L -v -n`

---

# 📄 System Logs

System logs on Linux are a set of files that contain information about the system and the activities taking place on it. These logs are important for:

- Monitoring and troubleshooting the system
- Gaining insight into system behavior and application activity
- Detecting security events and breaches
- Identifying unauthorized access, attempted attacks, or abnormal behavior

As **penetration testers**, we can:

- Analyze logs to identify weaknesses and attack vectors
- Monitor if our actions triggered IDS alerts or log entries
- Use findings to refine attack methods or improve system defenses

## 🔒 Logging Best Practices

- Set appropriate **log levels**
- Configure **log rotation**
- Secure storage & permissions
- Regular **log reviews** for anomalies

---

## 🧩 Types of Logs

| Type               | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| **Kernel Logs**     | Kernel, hardware drivers, system calls, stored in `/var/log/kern.log`       |
| **System Logs**     | System-wide events, reboots, services, stored in `/var/log/syslog`          |
| **Auth Logs**       | Login attempts, sudo usage, stored in `/var/log/auth.log`                   |
| **Application Logs**| App-specific logs (e.g., Apache, MySQL), stored in `/var/log/<app>/...`     |
| **Security Logs**   | Events from tools like UFW, Fail2Ban, auditd, etc.                          |

---

## 🧠 Kernel Logs

- Store kernel-level messages: hardware, system calls, and critical errors
- Location: `/var/log/kern.log`
- Useful for identifying:
  - Outdated/vulnerable drivers
  - System crashes or DoS conditions
  - Suspicious system calls or kernel-level malware

---

## 🖥️ System Logs

- Store general system events: service startups, logins, CRON jobs, reboots
- Location: `/var/log/syslog`
- Sample:
Feb 28 2023 15:04:22 server sshd[3010]: Failed password for htb-student from 10.14.15.2 port 50223 ssh2
Feb 28 2023 15:07:19 server sshd[3010]: Accepted password for htb-student from 10.14.15.2 port 50223 ssh2


---

## 🔑 Authentication Logs

- Focused on login attempts, sudo usage, and session starts
- Location: `/var/log/auth.log`
- Sample:
Feb 28 2023 18:15:01 sshd[5678]: Accepted publickey for admin from 10.14.15.2 port 43210 ssh2
Feb 28 2023 18:15:03 sudo: admin : COMMAND=/bin/bash


---

## 📦 Application Logs

- Store logs for individual applications
- Help identify misconfigurations, data exposure, or broken functionality
- Common locations:

| Service      | Log Path                                      |
|--------------|-----------------------------------------------|
| Apache       | `/var/log/apache2/access.log`                 |
| Nginx        | `/var/log/nginx/access.log`                   |
| OpenSSH      | `/var/log/auth.log` (Ubuntu) or `/var/log/secure` (RHEL) |
| MySQL        | `/var/log/mysql/mysql.log`                    |
| PostgreSQL   | `/var/log/postgresql/postgresql-*.log`        |
| systemd-journald | `/var/log/journal/`                         |

- Sample entry:
2023-03-07T10:15:23+00:00 servername privileged.sh: htb-student accessed /root/hidden/api-keys.txt


---

## 🛡️ Security Logs

- Include logs from firewalls, IDS, and other security tools
- Common paths:
- `/var/log/fail2ban.log` (Fail2Ban)
- `/var/log/ufw.log` (UFW firewall)
- `/var/log/audit/audit.log` (auditd)
- `/var/log/syslog` or `/var/log/auth.log` (general security events)

- Used for:
- Log correlation & anomaly detection
- Tracking brute-force attacks, suspicious processes
- Tuning WAF/firewall rule sets during testing

---

## 🧰 Useful Commands

| Command          | Purpose                               |
|------------------|----------------------------------------|
| `tail -f`         | Live log monitoring                    |
| `grep`            | Search log contents                    |
| `less` or `more`  | Scroll through logs                    |
| `logrotate`       | Manage & rotate logs automatically     |

---

- Regular log analysis = one of the most powerful **passive recon** methods you have.  
  
Stay stealthy. Stay paranoid. Stay elite. 🖤
