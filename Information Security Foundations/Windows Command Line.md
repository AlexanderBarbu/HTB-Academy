
# CMD.exe Overview
- **Command Prompt (cmd.exe / CMD)** is the default command line interpreter in Windows.  
- Based on the old **COMMAND.COM** from DOS.  
- Found on nearly all Windows OS versions.  
- Executes commands directly via the operating system.  
- Can perform powerful tasks (e.g., changing user passwords, checking network status).  
- Lightweight compared to GUI tools (uses fewer CPU & memory resources).  
- Still relevant today despite the popularity of **PowerShell**.

---
# Accessing CMD
There are multiple ways to access Command Prompt, depending on preference and available resources.

### Local vs. Remote Access
- **Local Access**
  - Direct physical (or virtual via VM) access to the machine.  
  - Does not require network connectivity.  
  - Access via peripherals (monitor, keyboard, mouse).  
  - Common methods:
    - **Windows + R → `cmd`**
    - Navigate to **C:\Windows\System32\cmd.exe**

- **Remote Access**
  - Allows a system administrator to manage machines across regions/buildings.  
  - Chosen based on factors like:
    - Physical distance from the user/machine.  
    - Whether the user is active on their machine.  
    - Network connectivity status.  
  - Enables maintenance and troubleshooting without direct physical presence.  

## Getting help

Although internet can help with finding the right syntax and function of a command sometimes, we dont have access to it. We can get help inside the Command Line by typing `help` before a command or `/?` after it. Typing `help` on its own list the commands available.

## Useful keys
|**Key/Command**|**Description**|
|:-:|---|
|doskey /history|doskey /history will print the session's command history to the terminal or output it to a file when specified.|
|page up|Places the first command in our session history to the prompt.|
|page down|Places the last command in history to the prompt.|
|⇧|Allows us to scroll up through our command history to view previously run commands.|
|⇩|Allows us to scroll down to our most recent commands run.|
|⇨|Types the previous command to prompt one character at a time.|
|⇦|N/A|
|F3|Will retype the entire previous entry to our prompt.|
|F5|Pressing F5 multiple times will allow you to cycle through previous commands.|
|F7|Opens an interactive list of previous commands.|
|F9|Enters a command to our prompt based on the number specified. The number corresponds to the commands place in our history.|
# System Navigation   
  
## Overview  
- Goal: Navigate and explore the Windows file system using Command Prompt  
- Core Tasks:  
- List directory contents  
- Identify current location  
- Move between directories  
- Understand file system structure  
  
---  
  
## Listing a Directory (`dir`)  
  
### Purpose  
- Displays contents of the current directory (files & folders)  
  
### Key Points  
- Default usage:  
- Shows all files and folders in current working directory  
- Supports additional arguments for filtering and advanced search  
- Help option:  
- `/ ?` → Displays all available options and usage  
  
### Why It Matters  
- First step in reconnaissance  
- Helps identify:  
- Interesting files  
- Hidden structure  
- Potential targets (configs, scripts, logs)  
  
---  
  
## Finding Current Location (`cd` / `chdir`)  
  
### Purpose  
- Displays current working directory  
  
### Key Concept: Current Working Directory  
- The directory you are currently operating in  
- All commands reference this location unless another path is specified  
  
### Behavior  
- Running `cd` or `chdir` without arguments:  
- Returns current directory path  
  
### Importance  
- Prevents confusion when navigating  
- Critical for:  
- File access  
- Command execution  
- Path resolution  
  
---  
  
## Moving Around (`cd` / `chdir`)  
  
### Purpose  
- Change current working directory  
  
### How It Works  
- Accepts a target directory as argument  
- Moves you from current directory to specified one  
  
### Path Types  
  
| Path Type     | Description                  |
| ------------- | ---------------------------- |
| Relative Path | Based on current directory   |
| Absolute Path | Full path starting from root |
  
### Relative Path  
- Defined in relation to current directory  
- Example concept:  
- Move into a subfolder from current location  
  
### Absolute Path  
- Full path from root of filesystem  
- Independent of current location  
  
### Why This Matters  
- Efficient navigation  
- Essential for scripting and automation  
- Reduces errors when accessing files  
  
---  
  
## File System Exploration  
  
### What You’re Doing  
- Traversing directories  
- Identifying structure and hierarchy  
  
### What to Look For  
- User directories  
- Configuration files  
- Logs and backups  
- Installed applications  
  
---  
  
## Adversary Perspective (Quick Insight)  
  
### "Juicy" Targets  
- Sensitive directories may contain:  
- Credentials  
- Config files  
- Scripts  
- Logs  
  
### Why It Matters  
- Navigation is the foundation of:  
- Enumeration  
- Privilege escalation  
- Data exfiltration  
  
---  

## Root Directory  
  
### Definition  
- The **topmost directory** in the file system hierarchy  
- Contains everything else  
  
### Windows Root  
- `C:\` → Default root directory  
- Historical context:  
- `A:\`, `B:\` → Floppy drives  
- `C:\` → First internal hard drive  
  
### Why It Matters  
- All absolute paths start from root  
- Acts as the "anchor" of the filesystem  
  
---  
  
## Absolute vs Relative Paths  
  
### Absolute Path  
  
#### Definition  
- Full path starting from root directory  
  
#### Example Structure  
- `C:\Users\htb\Pictures`  
  
#### Characteristics  
- Independent of current working directory  
- Always resolves to the same location  
  
---  
  
### Relative Path  
  
#### Definition  
- Path based on current working directory  
  
#### Key Symbols  
  
| Symbol | Meaning |  
|--------|--------|  
| `.` | Current directory |  
| `..` | Parent directory |  
  
#### Example Concept  
- If current directory is `C:\htb`  
- `.\Pictures` → `C:\htb\Pictures`  
  
#### Characteristics  
- Depends on current location  
- Shorter and faster to type  
- Riskier if you lose track of where you are  
  
---  
  
## Moving Through the File System  
  
### Going Up the Hierarchy  
  
- Use `..` to move up one level  
  
### Chaining Movement  
- Combine multiple `..` to climb directories  
  
#### Concept  
- From: `C:\Users\htb\Pictures`  
- Move to: `C:\`  
- Achieved by chaining upward traversal  
  
### Why This Is Powerful  
- Fast navigation without typing full paths  
- Essential for efficiency during enumeration  
  
---  
  
## File System Exploration  
  
### Goal  
- Understand structure  
- Locate valuable data  
  
### Challenges  
- Manually navigating directories is slow  
- Running `dir` repeatedly is inefficient  
  
---  
  
## Tree Command (`tree`)  
  
### Purpose  
- Displays directory structure recursively  
  
### Default Behavior  
- Shows folder hierarchy of a given path  
  
### Enhanced Usage  
  
| Parameter | Description |  
|----------|------------|  
| `/F` | Includes files in output |  
  
### Why It’s Useful  
- Visual overview of entire directory structure  
- Helps identify:  
- Interesting folders  
- Hidden nesting  
- Project layouts  
  
---  
  
## Adversary Perspective  
  
### What to Hunt For  
- Configuration files  
- Project directories  
- Backup files  
- Credential storage (password files)  
  
### Why `tree /F` Is OP  
- Quickly maps entire system areas  
- Saves time during enumeration  
- Helps prioritize targets fast  
  
---

## Interesting Directories (Windows) – Attacker Perspective  
- Certain directories in Windows are **high-value targets** during enumeration  
- Reasons:  
- Weak permissions  
- High user interaction  
- Contain useful data (apps, temp files, configs)  
  
---  
  
## Key Directories  
  
| Name | Location | Description |  
|----------------------|--------------------------------------|-------------|  
| `%SYSTEMROOT%\Temp` | `C:\Windows\Temp` | Global temp directory with **full access for all users** |  
| `%TEMP%` | `C:\Users\<user>\AppData\Local\Temp` | User-specific temp directory |  
| `%PUBLIC%` | `C:\Users\Public` | Shared directory accessible by all users |  
| `%ProgramFiles%` | `C:\Program Files` | Installed 64-bit applications |  
| `%ProgramFiles(x86)%`| `C:\Program Files (x86)` | Installed 32-bit applications |  
  
---  
  
## Breakdown & Use Cases  
  
### `%SYSTEMROOT%\Temp` → `C:\Windows\Temp`  
  
- Permissions:  
- Read / Write / Execute for **all users**  
- Use Cases:  
- Drop payloads as low-priv user  
- Store temporary tools/scripts  
- Risk:  
- More likely to be monitored  
  
---  
  
### `%TEMP%` → User Temp Directory  
  
- Path:  
- `C:\Users\<user>\AppData\Local\Temp`  
- Permissions:  
- Full control for the specific user  
- Use Cases:  
- Store tools after user compromise  
- Execute files without admin rights  
- Advantage:  
- Less noisy than system-wide temp  
  
---  
  
### `%PUBLIC%` → Shared Directory  
  
- Path:  
- `C:\Users\Public`  
- Permissions:  
- Full access for all interactive users  
- Use Cases:  
- Drop files accessible across accounts  
- Share payloads between sessions  
- Advantage:  
- Often **less monitored than Temp**  
  
---  
  
### `%ProgramFiles%` → 64-bit Applications  
  
- Path:  
- `C:\Program Files`  
- Use Cases:  
- Identify installed software  
- Discover:  
- Attack surface  
- Misconfigurations  
- Outdated apps  
  
---  
  
### `%ProgramFiles(x86)%` → 32-bit Applications  
  
- Path:  
- `C:\Program Files (x86)`  
- Use Cases:  
- Same as above but for 32-bit apps  
- Why It Matters:  
- Legacy software = higher chance of vulnerabilities  
  
---  
  
## Attacker Mindset  
  
### What You’re Looking For  
  
- Writable directories  
- Misconfigured permissions  
- Installed applications  
- Files like:  
- `.config`  
- `.log`  
- `.xml`  
- backup files  
  
---  
  
## Practical Goals  
  
- **File Drop Locations**  
- Temp directories  
- Public directory  
  
- **Reconnaissance**  
- Installed software  
- System structure  
  
- **Privilege Escalation Leads**  
- Weak permissions  
- Vulnerable applications  
  
---