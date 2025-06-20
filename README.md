# wsl-cpu-monitor
Real-time CPU and storage monitoring for Windows host and WSL2 environments via PowerShell and Python

![image](https://github.com/user-attachments/assets/60094c8c-e113-4d9c-b63b-c89380c0f3ab)

---

**Overview**

this is a tool for real-time monitoring of CPU usage and storage status for both the Windows host and the WSL2 environment. On the Windows side, it generates and executes a temporary PowerShell script to obtain the necessary data, while on the WSL side, it directly collects the information via commands such as `/proc/stat` for CPU statistics and `df -h /` for storage details.

---

**Execution**

Run the tool with default settings by simply executing:
```bash
python3 wsl-cpu-monitor.py
```
This will launch the monitor without any additional configuration.

---

**Command-Line Arguments Example**

You can also customize the tool's behavior using the following command-line arguments:

- **`--powershell-path`**
  Specify the full path to the PowerShell executable.
  *Example:*
  ```bash
  --powershell-path="/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
  ```

- **`--temp_dir`**
  Define the temporary directory where the PowerShell script will be saved.
  *Example:*
  ```bash
  --temp_dir="/mnt/c/Windows/Temp"
  ```

- **`--update_interval`**
  Set the screen update interval in seconds. This controls how frequently the UI refreshes.
  *Example:*
  ```bash
  --update_interval=0.25
  ```

- **`--powershell_encoding`**
  Choose the text encoding for PowerShell output (e.g., "utf-8").
  *Example:*
  ```bash
  --powershell_encoding="utf-8"
  ```

These arguments enable you to tweak the tool's settings on the fly without modifying the source code.

**Notes**

Since the tool integrates WSL2 with the Windows host, you may encounter issues related to path conversion or permissions depending on your environment. To exit the program, simply press the 'q' key in the terminal.
