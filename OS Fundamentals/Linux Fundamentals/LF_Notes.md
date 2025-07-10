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
| **Config as text files**                 | e.g., `/etc/passwd` stores user data in plain text format.                |

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
