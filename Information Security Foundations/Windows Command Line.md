# Windows Command Line Fundamentals

## CMD.exe Overview
- **Command Prompt (cmd.exe / CMD)** is the default command line interpreter in Windows.  
- Based on the old **COMMAND.COM** from DOS.  
- Found on nearly all Windows OS versions.  
- Executes commands directly via the operating system.  
- Can perform powerful tasks (e.g., changing user passwords, checking network status).  
- Lightweight compared to GUI tools (uses fewer CPU & memory resources).  
- Still relevant today despite the popularity of **PowerShell**.

---
## Accessing CMD
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
