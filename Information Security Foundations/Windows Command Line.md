
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

##  Working with Directories & Files (CMD)

- Focus: Creating and managing directories
- Builds on:
  - `cd` (navigation)
  - `dir` (listing)
  - `tree` (structure visualization)

---

## Directories Recap

### Definition
- A directory = container for files and other directories
- Forms the hierarchical structure of the filesystem

---

## File System Mental Model (Refined)

| Concept   | Meaning                     |
|----------|----------------------------|
| `C:\`     | Root (base of everything)  |
| `Users`   | Top-level directory        |
| `htb`     | User-specific folder       |
| Files     | Final objects (data)       |

---

## Viewing & Listing Directories

### Current Location
- `cd`
  - Shows current working directory

---

### List Contents
- `dir`
  - Displays:
    - Files
    - Subdirectories

---

### Full Structure
- `tree`
  - Displays full directory hierarchy

#### With Files
- `tree /F`
  - Includes files in output

---

## Combining Commands (Workflow)

### Typical Flow
- Check location → `cd`
- List contents → `dir`
- Map structure → `tree /F`

### Why Combine Them
- Faster exploration
- Better situational awareness
- Reduced manual navigation

---

## Creating Directories

### Commands

| Command | Description |
|--------|-------------|
| `md`   | Make directory |
| `mkdir`| Make directory (same as md) |

---

### Behavior
- Creates a new folder in current directory
- Can also create directories using full path

---

## Key Concepts

### Relative Creation
- Directory created relative to current location

### Absolute Creation
- Directory created using full path from root

---

## Why This Matters

### System Usage
- Organize files
- Structure data logically

### Cybersecurity Perspective
- Create staging areas for:
  - Tools
  - Payloads
  - Data collection

---

## Attacker Mindset

### Use Cases
- Drop tools in writable directories
- Create hidden working folders
- Maintain persistence (depending on context)

---

## TL;DR

- Directories = structure backbone  
- `cd` → where you are  
- `dir` → what exists  
- `tree` → full map  
- `md` / `mkdir` → create folders  
- Combine commands = faster workflow  

---


  
## Host Enumeration – Types of Information  

- Goal: Build a **clear picture of the target system**  
- Avoid random searching → follow structured methodology  
- Focus on **what matters**, not everything  
  
---  
  
## Why Enumeration Matters  
  
- Saves time (no blind searching)  
- Helps identify:  
- Attack surface  
- Misconfigurations  
- Privilege escalation paths  
- Builds **situational awareness**  
  
---  
  
## Core Information Categories  
  
### 1. General System Information  
  
#### What It Includes  
- Hostname  
- OS Name  
- OS Version  
- OS Configuration  
- Installed patches / hotfixes  
  
#### Why It Matters  
- Identify:  
- Vulnerabilities  
- Missing patches  
- System type (server, workstation)  
  
---  
  
### 2. Networking Information  
  
#### What It Includes  
- Host IP address  
- Network interfaces  
- Accessible subnets  
- DNS servers  
- Known hosts  
- Network resources:  
- Shares  
- Domain resources  
- Devices (printers, etc.)  
- Firewall configuration  
  
#### Why It Matters  
- Map the network  
- Discover:  
- Lateral movement paths  
- Other targets  
- Internal services  
  
---  
  
### 3. Basic Domain Information  
  
#### What It Includes  
- Domain / Workgroup name  
- Logon server  
  
#### Why It Matters  
- Detect:  
- Active Directory presence  
- Enables:  
- Domain enumeration  
- Privilege escalation in domain environments  
  
---  
  
### 4. User Information  
  
#### What It Includes  
- User accounts  
- Local groups  
- Environment variables  
- Running processes (tasks)  
- Scheduled tasks  
- Services  
- Security tools:  
- Antivirus  
- IDS/IPS  
  
#### Why It Matters  
- Identify:  
- Current privileges  
- Potential escalation paths  
- Persistence mechanisms  
  
---  
  
## Key Enumeration Questions  
  
### Always Ask Yourself  
  
- What system information can I extract?  
- What other systems is this host connected to?  
- What access do I currently have?  
- What can I do with this access?  
  
---  
  
## Methodology Mindset  
  
### Don’t Do This  
- Random commands  
- Blind searching  
- “try everything and hope”  
  
### Do This Instead  
- Follow structured categories  
- Prioritize valuable data  
- Filter noise  
  
---  
  
## Practical Goal  
  
- Turn raw data → **actionable intel**  
- Build:  
- Attack path  
- Exploitation plan  
- Privilege escalation strategy  
  
---

## Why Do We Need This Information?  
  
### Core Idea  
- Enumeration = **your roadmap**  
- Without it → you're blind, guessing, wasting time  
  
---  
  
## Real Scenario (Assumed Breach)  
  
### Situation  
- You have:  
- Initial access  
- Low-privileged user  
  
### Goal  
- Escalate privileges → admin / SYSTEM  
  
---  
  
## What You Need to Figure Out  
  
### User Context  
  
- Which user am I?  
- What groups do I belong to?  
- What privileges do I have?  
  
---  
  
### System Access  
  
- What can I access locally?  
- What files/directories are available?  
- What misconfigurations exist?  
  
---  
  
### Network Access  
  
- What systems can I reach?  
- Any shared resources?  
- Domain presence?  
  
---  
  
### Execution Context  
  
- What processes are running?  
- What services exist?  
- Any scheduled tasks?  
  
---  
  
## Key Insight (THIS is important af)  
  
### ❌ Wrong Mindset  
- "System is patched → nothing to exploit"  
  
### ✅ Correct Mindset  
- Humans misconfigure systems ALL the time  
  
👉 Most real-world wins:  
- Weak permissions  
- Bad configs  
- Exposed credentials  
- Poor security practices  
  
---  
  
## Why Thorough Enumeration Wins  
  
- Finds:  
- Hidden attack paths  
- Privilege escalation vectors  
- Lateral movement opportunities  
  
- Prevents:  
- Missing easy wins  
- Tunnel vision on CVEs only  
  
---  
  
## How Do We Get This Information?  
  
## ⚡ `systeminfo` – The Quick Recon Tool  
  
### Purpose  
- One command → massive info dump  
  
---  
  
### What It Gives You  
  
- Hostname  
- OS Name / Version / Build  
- Installed patches (hotfixes)  
- Network info (IPs)  
- Domain membership  
- Hardware details  
  
---  
  
### Why It's OP  
  
- Minimal footprint (stealthier)  
- Fast overview of system  
- Great starting point  
  
---  
  
## Attacker Use Case  
  
### Workflow  
  
1. Run `systeminfo`  
2. Extract:  
- OS version  
- Patch level  
3. Search:  
- Google / ExploitDB  
4. Check:  
- Known exploits  
- PrivEsc vectors  
  
---  
  
## Defender Use Case  
  
- Troubleshooting  
- System diagnostics  
- Patch verification  
  
---  
  
## Key Advantage  
  
- 1 command instead of many  
- Less noise = less detection risk  
  
---  
  
## TL;DR  
  
- Enumeration = your attack blueprint  
- Focus on:  
- user  
- system  
- network  
- Don’t trust "fully patched" systems  
- `systeminfo` = fast, stealthy recon  
- Smart enumeration > blind exploitation 💀

---
## Why Do We Need This Information?  
  
### Core Idea  
- Enumeration = **your roadmap**  
- Without it → you're blind, guessing, wasting time  
  
---  
  
## Real Scenario (Assumed Breach)  
  
### Situation  
- You have:  
- Initial access  
- Low-privileged user  
  
### Goal  
- Escalate privileges → admin / SYSTEM  
  
---  
  
## What You Need to Figure Out  
  
### User Context  
  
- Which user am I?  
- What groups do I belong to?  
- What privileges do I have?  
  
---  
  
### System Access  
  
- What can I access locally?  
- What files/directories are available?  
- What misconfigurations exist?  
  
---  
  
### Network Access  
  
- What systems can I reach?  
- Any shared resources?  
- Domain presence?  
  
---  
  
### Execution Context  
  
- What processes are running?  
- What services exist?  
- Any scheduled tasks?  
  
---  
  
## Key Insight (THIS is important af)  
  
### ❌ Wrong Mindset  
- "System is patched → nothing to exploit"  
  
### ✅ Correct Mindset  
- Humans misconfigure systems ALL the time  
  
👉 Most real-world wins:  
- Weak permissions  
- Bad configs  
- Exposed credentials  
- Poor security practices  
  
---  
  
## Why Thorough Enumeration Wins  
  
- Finds:  
- Hidden attack paths  
- Privilege escalation vectors  
- Lateral movement opportunities  
  
- Prevents:  
- Missing easy wins  
- Tunnel vision on CVEs only  
  
---  
  
## How Do We Get This Information?  
  
## ⚡ `systeminfo` – The Quick Recon Tool  
  
### Purpose  
- One command → massive info dump  
  
---  
  
### What It Gives You  
  
- Hostname  
- OS Name / Version / Build  
- Installed patches (hotfixes)  
- Network info (IPs)  
- Domain membership  
- Hardware details  
  
---  
  
### Why It's OP  
  
- Minimal footprint (stealthier)  
- Fast overview of system  
- Great starting point  
  
---  
  
## Attacker Use Case  
  
### Workflow  
  
1. Run `systeminfo`  
2. Extract:  
- OS version  
- Patch level  
3. Search:  
- Google / ExploitDB  
4. Check:  
- Known exploits  
- PrivEsc vectors  
  
---  
  
## Defender Use Case  
  
- Troubleshooting  
- System diagnostics  
- Patch verification  
  
---  
  
## Key Advantage  
  
- 1 command instead of many  
- Less noise = less detection risk  
  
---

## Finding Files & Directories (CMD) – Enumeration & Search
- Goal: Efficiently **locate files, directories, and data**  
- Critical for:  
- Enumeration  
- Data discovery  
- Privilege escalation  
  
---  
  
## Why File Enumeration Matters  
  
- Finds:  
- Credentials (👀 passwords.txt classic)  
- Config files  
- Logs  
- Sensitive data  
- Saves time vs manual browsing  
- Helps build attack paths fast  
  
---  
  
## Searching Files & Apps  
  
## `where` Command  
  
### Purpose  
- Locate files/executables on system  
  
---  
  
### Basic Usage  
  
- Searches:  
- Environment PATH directories by default  
  
---  
  
### Behavior  
  
- Works automatically for:  
- System binaries (e.g. `calc.exe`)  
- Fails if file is outside PATH  
  
---  
  
## Recursive Search (`/R`)  
  
### Purpose  
- Search entire directory tree  
  
### Usage Concept  
- Specify base path → search everything inside  
  
---  
  
## Wildcards  
  
### Supported Patterns  
  
| Pattern | Meaning |  
|--------|--------|  
| `*` | Any characters |  
| `*.csv`| All CSV files |  
  
---  
  
### Use Case  
- Find all files of specific type  
  
---  
  
## Searching Inside Files  
  
## `find` Command  
  
### Purpose  
- Search for **text strings** inside files  
  
---  
  
### Key Features  
  
- Simple string matching  
- Works on:  
- Files  
- Command output  
  
---  
  
### Important Switches  
  
| Switch | Description |  
|--------|-------------|  
| `/V` | NOT match (exclude string) |  
| `/N` | Show line numbers |  
| `/I` | Ignore case |  
  
---  
  
### Limitations  
- No wildcard/regex support  
- Basic functionality only  
  
---  
  
## Advanced Search  
  
## `findstr` Command  
  
### Purpose  
- Advanced version of `find`  
  
---  
  
### Capabilities  
  
- Pattern matching  
- Regex support  
- Wildcards  
- Multiple conditions  
  
---  
  
### Comparison  
  
| Tool | Capability Level |  
|----------|-----------------|  
| `find` | Basic |  
| `findstr`| Advanced (like `grep`) |  
  
---  
  
## Evaluating & Comparing Files  
  
## `comp`  
  
### Purpose  
- Compare files byte-by-byte  
  
---  
  
### Features  
  
- Shows:  
- Differences between files  
- Default:  
- Decimal output  
  
---  
  
### Useful Switches  
  
| Switch | Description |  
|--------|-------------|  
| `/A` | ASCII format |  
| `/L` | Show line numbers |  
  
---  
  
## Other Tools  
  
| Command | Purpose |  
|--------|--------|  
| `fc` | Compare files (more readable) |  
| `sort` | Sort file content |  
  
---  
  
## Attacker Mindset  
  
### What to Search For  
  
- Filenames:  
- `password`  
- `config`  
- `backup`  
- `admin`  
- File types:  
- `.txt`  
- `.xml`  
- `.ini`  
- `.log`  
- `.csv`  
  
---  
  
### Strategy  
  
1. Locate files → `where /R`  
2. Filter types → wildcards  
3. Search inside → `findstr`  
4. Analyze differences → `comp` / `fc`  
  
---  

# Managing Services (CMD)  
  
## Overview  
- Services = background processes managed by Windows  
- Critical for:  
- System operation  
- Security  
- Persistence  
  
---  
  
## Why Services Matter  
  
### Administrator Perspective  
- Monitor system health  
- Start/stop applications  
- Troubleshoot issues  
  
---  
  
### Attacker Perspective  
- Discover security software  
- Disable defenses  
- Abuse weak service configurations  
- Gain persistence  
  
---  
  
## Typical Attacker Goals  
  
### 1. Enumerate Running Services  
- Identify:  
- Antivirus  
- Monitoring tools  
- Vulnerable services  
  
---  
  
### 2. Disable Security Tools  
- AV  
- EDR  
- Logging services  
  
⚠️ Extremely noisy in real environments  
(Defenders absolutely love when someone kills Defender at 3AM. Free SIEM dopamine.)  
  
---  
  
### 3. Modify Existing Services  
- Change:  
- Executable path  
- Startup behavior  
- Permissions  
  
---  
  
# Service Controller (`sc`)  
  
## What is `sc`?  
  
### Definition  
- Windows Service Controller utility  
- Built-in executable for:  
- Querying  
- Managing  
- Modifying services  
  
---  
  
## Capabilities  
  
| Action | Description |  
|--------|-------------|  
| Query | View services |  
| Start | Start services |  
| Stop | Stop services |  
| Create | Create new services |  
| Config | Modify service settings |  
| Delete | Remove services |  
  
---  
  
## Local & Remote Management  
  
### Supports  
- Local host management  
- Remote host management  
  
---  
  
## Why `sc` Is Powerful  
  
- Native Windows binary  
- No extra tools required  
- Useful for:  
- Admins  
- Attackers  
- Red Team ops  
  
---  
  
## Alternative Tools  
  
| Tool | Purpose |  
|------|---------|  
| `WMIC` | Query/manage system components |  
| `tasklist` | View running tasks/processes |  
  
---  
  
## Attacker Enumeration Focus  
  
### What to Look For  
  
- Weak permissions  
- Unquoted service paths  
- Services running as:  
- SYSTEM  
- Administrator  
  
---  
  
### Interesting Service Properties  
  
- Binary path  
- Startup type  
- Service account  
- Current state  
  
---  
  
## Service Abuse Possibilities  
  
### Common Misconfigurations  
  
- Writable service binaries  
- Writable service folders  
- Weak ACLs  
- Unquoted paths  
  
---  
  
## Why This Matters  
  
### Potential Outcomes  
- Privilege escalation  
- Persistence  
- Defense evasion  
  
---

## Default Behavior  
  
### Running Without Arguments  
- Displays:  
- Help menu  
- Syntax  
- Examples  
  
---  
  
## Syntax Structure  
  
| Component | Purpose |  
|----------|---------|  
| `sc` | Service Controller command |  
| `<server>` | Remote target system |  
| `[command]` | Action to perform |  
| `[service name]` | Target service |  
  
---  
  
## Remote Management  
  
### Server Syntax  
- Uses:  
- `\\ServerName`  
  
### Why It Matters  
- Manage services remotely  
- Useful in:  
- Administration  
- Lateral movement scenarios  
  
---  
  
# Querying Services  
  
## Why Query Services?  
  
### Attacker Perspective  
- Identify:  
- Antivirus  
- EDR  
- Monitoring tools  
- Vulnerable services  
  
### Defender Perspective  
- Troubleshooting  
- Monitoring  
- Diagnostics  
  
---  
  
## Enumerating Running Services  
  
### Command Concept  
- Query all active Win32 services  
  
---  
  
## ⚠️ Important Syntax Detail  
  
### Spacing Matters  
  
| Syntax | Valid? |  
|--------|--------|  
| `type= service` | ✅ Correct |  
| `type=service` | ❌ Wrong |  
| `type =service` | ❌ Wrong |  
  
Windows CMD parser casually sabotaging humans since the 90s. Ancient ritual spacing technology.  
  
---  
  
# Understanding Service Output  
  
## Key Fields  
  
| Field | Meaning |  
|------|---------|  
| `SERVICE_NAME` | Internal service name |  
| `DISPLAY_NAME` | Human-readable name |  
| `TYPE` | Service execution type |  
| `STATE` | Current status |  
| `WIN32_EXIT_CODE` | Service exit status |  
| `CHECKPOINT` | Startup/shutdown progress |  
| `WAIT_HINT` | Estimated wait time |  
  
---  
  
## Service States  
  
| State Value | Meaning |  
|-------------|---------|  
| `1` | STOPPED |  
| `4` | RUNNING |  
  
---  
  
## Service Types  
  
| Type | Meaning |  
|------|---------|  
| `WIN32` | Standard Windows service |  
| `WIN32_OWN_PROCESS` | Dedicated process |  
| `WIN32_SHARE_PROCESS` | Shared process |  
  
---  
  
# Useful Queries  
  
## Active Services  
- Enumerate currently running services  
  
---  
  
## All Services  
- Include stopped services and drivers  
  
---  
  
## Drivers Only  
- Enumerate active drivers  
  
---  
  
## Interactive Services  
- Find services interacting with desktop/user  
  
---  
  
# Why This Enumeration Matters  
  
## Valuable Findings  
  
### Security Software  
- Defender  
- AV  
- EDR  
  
### Potential PrivEsc Targets  
- Weak service permissions  
- Misconfigured binaries  
- Unquoted paths  
  
### Operational Intel  
- Running applications  
- Installed software ecosystem  
  
---  
  
# Attacker Methodology  
  
## Typical Workflow  
  
1. Enumerate services  
2. Identify:  
- security products  
- custom apps  
- weak configs  
3. Investigate:  
- permissions  
- executable paths  
4. Attempt:  
- privilege escalation  
- persistence  
  
---