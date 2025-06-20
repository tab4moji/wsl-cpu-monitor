#!/usr/bin/env python3
"""
WSL CPU Monitor

Changelog:
[1] 2025-06-20: Initial creation. Monitoring tool for CPU usage and storage information on both Windows hosts and WSL2 environments.
       Keywords: cpu, storage, PowerShell, WSL, curses, argparse.
[2] 2025-06-20: Renamed variables and enhanced comments.
       Keywords: HEARTBEAT_SPINNER_CHARS, powershell_path, temp_script_path, updating_spinner_index, heartbeat_spinner_index.
[3] 2025-06-20: Refactored duplicate queue operations and JSON extraction into separate functions.
       Keywords: safe_queue_put, extract_json_from_buffer.
[4] 2025-06-20: Made the code PEP 8 compliant, removed magic numbers, and replaced hardcoded paths with constants.
       Keywords: PEP8, MAGIC_NUMBER, DEFAULT_POWERSHELL_PATH, DEFAULT_TEMP_DIR, POWERSHELL_ENCODING, DASH_LINE_LENGTH.
"""

import time
import curses
import subprocess
import json
import queue
import os
import tempfile
import threading
import argparse

# Configurations
DEFAULT_POWERSHELL_PATH = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
DEFAULT_TEMP_DIR = "/mnt/c/Windows/Temp"
POWERSHELL_ENCODING = "utf-8"
DASH_LINE_LENGTH = 70

# Spinner characters for updating status and heartbeat animations
UPDATING_SPINNER_CHARS = ['-', '\\', '|', '/']
HEARTBEAT_SPINNER_CHARS = ['.', 'o', 'O', 'o']  # Corrected from "HEATBEAT" to "HEARTBEAT"

DEFAULT_UPDATE_INTERVAL = 1 / len(HEARTBEAT_SPINNER_CHARS)  # Interval for screen updates in seconds

# PowerShell script content (unchanged besides indent adjustments)
POWERSHELL_SCRIPT_CONTENT = r"""
$ErrorActionPreference = "Stop"
$OutputEncoding = [System.Text.Encoding]::UTF8
$Cache_Update_Interval = 2
$SmaWindow = 10
$scale_factor = 1000 * 1000
$HostPrevTimes = @{}
$HostUsageHistory = @{}
$HostUsageHistory_idx = @{}
while ($true) {
    $data = @{}
    try {
        $cpuCounters = Get-Counter '\Processor(*)\% Processor Time' | Select-Object -ExpandProperty CounterSamples
        $overallCpu = $null
        $perCoreCpu = @()
        foreach ($counter in $cpuCounters) {
            if ($counter.InstanceName -eq '_Total') {
                $overallCpu = $counter.CookedValue
            } else {
                $perCoreCpu += @{ "Instance" = $counter.InstanceName; "Value" = $counter.CookedValue }
            }
        }
        $data.HostCpu = @{ "overall" = $overallCpu; "per_core" = $perCoreCpu; "error" = $null }
    } catch {
        $data.HostCpu = @{ "overall" = $null; "per_core" = $null; "error" = $_.Exception.Message }
    }
    try {
        $processes = Get-Process | Select-Object Id,ProcessName,CPU
        $procResults = @()
        foreach ($proc in $processes) {
            $procId = $proc.Id
            $cpuTime = $proc.CPU * $scale_factor
            if (-not $HostUsageHistory.ContainsKey($procId)) {
                $HostUsageHistory_idx[$procId] = 0
                $HostUsageHistory[$procId] = 1..$SmaWindow | ForEach-Object { 0.0 }
            }
            if ($HostPrevTimes.ContainsKey($procId)) {
                $diff = $cpuTime - $HostPrevTimes[$procId]
                $instUsage = [Math]::Max(0, $diff) / $Cache_Update_Interval * 100
            } else {
                $instUsage = 0.0
            }
            $HostPrevTimes[$procId] = $cpuTime
            $HostUsageHistory_idx[$procId] = ($HostUsageHistory_idx[$procId] + 1) % $SmaWindow
            $HostUsageHistory[$procId][$HostUsageHistory_idx[$procId]] = $instUsage
            $sma = ($HostUsageHistory[$procId] | Measure-Object -Sum).Sum / $HostUsageHistory[$procId].Count
            $procResults += @{ "Id" = $procId; "ProcessName" = $proc.ProcessName; "CPU" = $sma / $scale_factor}
        }
        $procResults = $procResults | Sort-Object -Property @{Expression={[double]$_.CPU};Descending=$true} | Select-Object -First 10
        $data.HostProcesses = @{ "top_10" = $procResults; "error" = $null }
    } catch {
        $data.HostProcesses = @{ "top_10" = $null; "error" = $_.Exception.Message }
    }
    try {
        $driveC = Get-PSDrive -Name C
        $used = $driveC.Used
        $free = $driveC.Free
        $total = $used + $free
        if ($total -ne 0) {
            $usagePercent = ($used / $total) * 100
        } else {
            $usagePercent = 0
        }
        $data.HostStorage = @{ "info" = @($usagePercent, $total, $used, $free); "error" = $null }
    } catch {
        $data.HostStorage = @{ "info" = $null; "error" = $_.Exception.Message }
    }
    try {
        ($data | ConvertTo-Json -Depth 5 -Compress)
    } catch {
        $data.HostStorage = @{ "info" = $null; "error" = $_.Exception.Message }
        ($data | ConvertTo-Json -Depth 5 -Compress)
    }
    Write-Host "---END_OF_DATA---"
    Start-Sleep -Seconds $Cache_Update_Interval
}
"""



def safe_queue_put(q, data):
    """Safely push data to a queue, popping older entries if full."""
    try:
        if q.full():
            q.get_nowait()
        q.put_nowait(data)
    except queue.Full:
        pass


def extract_json_from_buffer(buffer):
    """Extract JSON string from the given buffer containing the end-of-data marker.

    Returns:
        tuple: (json_string, error_message) where json_string is None if extraction fails.
    """
    json_str_raw = buffer.replace("---END_OF_DATA---", "").strip()
    json_start_index = json_str_raw.find('{')
    json_end_index = json_str_raw.rfind('}')
    if json_start_index == -1 or json_end_index == -1 or json_start_index >= json_end_index:
        return None, f"No valid JSON found in raw output. Raw: {json_str_raw[:200]}..."
    return json_str_raw[json_start_index: json_end_index + 1], None


def draw_progress_bar(usage, bar_length):
    """Return a string progress bar representation for a given usage percentage (0-100)."""
    filled = int(round(usage / 100 * bar_length))
    empty = bar_length - filled
    return "#" * filled + "." * empty


def get_wsl_storage_info():
    """Retrieve the storage usage information for the WSL root filesystem.

    Returns:
        tuple: (usage_info, error_message) where usage_info is a tuple (usage_percent, size, used, available) if successful.
    """
    cmd = "df -h /"
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5)
        lines = output.decode("utf-8", errors="replace").strip().splitlines()
        if len(lines) < 2:
            return None, "df command returned insufficient data"
        parts = lines[1].split()
        if len(parts) < 5:
            return None, "Unexpected df output format"
        percent_str = parts[4]
        size = parts[1]
        used = parts[2]
        available = parts[3]
        usage_percent = float(percent_str.strip('%'))
        return (usage_percent, size, used, available), None
    except subprocess.TimeoutExpired:
        return None, "df command timed out"
    except Exception as e:
        return None, str(e)


class CpuUsage:
    """Class for monitoring WSL CPU usage by reading /proc/stat."""
    def __init__(self):
        self.previous_stats = self._read_cpu_stats()

    def _read_cpu_stats(self):
        stats = {}
        try:
            with open("/proc/stat", "r") as file:
                for line in file:
                    if line.startswith("cpu") and line[3].isdigit():
                        parts = line.split()
                        try:
                            user = int(parts[1])
                            nice = int(parts[2])
                            system = int(parts[3])
                            idle = int(parts[4])
                            iowait = int(parts[5]) if len(parts) > 5 else 0
                            irq = int(parts[6]) if len(parts) > 6 else 0
                            softirq = int(parts[7]) if len(parts) > 7 else 0
                            steal = int(parts[8]) if len(parts) > 8 else 0
                        except Exception:
                            continue
                        idle_total = idle + iowait
                        non_idle = user + nice + system + irq + softirq + steal
                        total = idle_total + non_idle
                        stats[parts[0]] = (idle_total, total)
        except Exception as e:
            print("Error reading /proc/stat:", e)
        return stats

    def get_cpu_percentages(self):
        """Calculate and return CPU usage percentages for each core."""
        new_stats = self._read_cpu_stats()
        cpu_percentages = []
        for cpu in new_stats:
            if cpu in self.previous_stats:
                prev_idle, prev_total = self.previous_stats[cpu]
                curr_idle, curr_total = new_stats[cpu]
                total_delta = curr_total - prev_total
                idle_delta = curr_idle - prev_idle
                if total_delta == 0:
                    cpu_percent = 0.0
                else:
                    cpu_percent = (total_delta - idle_delta) / total_delta * 100
            else:
                cpu_percent = 0.0
            cpu_percentages.append(cpu_percent)
        self.previous_stats = new_stats
        return cpu_percentages


def data_collector_process(data_queue, exit_event, config):
    """
    Process that collects monitoring data from both the Windows host (via PowerShell) and WSL.
    It writes a temporary PowerShell script and executes it,
    then continuously reads the JSON outputs from the script.
    """
    powershell_path = config.get("powershell_path", DEFAULT_POWERSHELL_PATH)
    powershell_encoding = config.get("powershell_encoding", POWERSHELL_ENCODING)
    windows_temp_directory = config.get("temp_dir", DEFAULT_TEMP_DIR)
    temp_script_path = None
    powershell_process = None
    try:
        fd, path = tempfile.mkstemp(suffix='.ps1', text=True, dir=windows_temp_directory)
        with os.fdopen(fd, 'w', encoding=powershell_encoding) as file:
            file.write(POWERSHELL_SCRIPT_CONTENT)
        temp_script_path = path
        try:
            # Convert WSL path to Windows path using wslpath utility
            wsl_to_windows_path_cmd = f"wslpath -w \"{temp_script_path}\""
            windows_script_path = subprocess.check_output(wsl_to_windows_path_cmd, shell=True).decode("utf-8").strip()
            final_script_path = windows_script_path
        except Exception as e:
            print(f"Error converting WSL path to Windows path using wslpath: {e}. Falling back to direct path (might fail).")
            final_script_path = temp_script_path
        # Construct PowerShell command line
        powershell_cmd = f'"{powershell_path}" -NoProfile -ExecutionPolicy Bypass -File "{final_script_path}"'
        powershell_cmd = powershell_cmd.replace('"', '\\"')
        bash_command = f'exec stdbuf --input=0 --output=0 --error=0 bash -c "{powershell_cmd}"'
        # Launch PowerShell process under bash
        powershell_process = subprocess.Popen(
            bash_command,
            bufsize=0,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            shell=True,
            start_new_session=True
        )
        wsl_cpu_monitor = CpuUsage()
        line_buffer = ""
        while not exit_event.is_set():
            # If PowerShell process terminated, report fatal error
            if powershell_process.poll() is not None:
                stderr_output = powershell_process.stderr.read().decode(powershell_encoding, errors="replace")
                current_data = {
                    'host_cpu': {'overall': None, 'per_core': None, 'error': f"PowerShell process terminated unexpectedly. Stderr: {stderr_output}"},
                    'host_processes': {'top_10': None, 'error': "PowerShell process terminated unexpectedly."},
                    'host_storage': {'info': None, 'error': "PowerShell process terminated unexpectedly."},
                    'wsl_cpu': {'per_core': None, 'error': "Loading... (PowerShell dead)"},
                    'wsl_storage': {'info': None, 'error': "Loading... (PowerShell dead)"},
                    'fatal': stderr_output
                }
                safe_queue_put(data_queue, current_data)
                break
            try:
                # Read a line from the PowerShell process output
                ps_line = powershell_process.stdout.readline().decode(powershell_encoding, errors="replace").strip()
                if ps_line:
                    line_buffer += ps_line
                    # Check for the end-of-data marker in the buffered output
                    if "---END_OF_DATA---" in line_buffer:
                        json_str, err = extract_json_from_buffer(line_buffer)
                        line_buffer = ""
                        if err:
                            error_msg = err
                            current_data = {
                                'host_cpu': {'overall': None, 'per_core': None, 'error': error_msg},
                                'host_processes': {'top_10': None, 'error': error_msg},
                                'host_storage': {'info': None, 'error': error_msg},
                                'wsl_cpu': {'per_core': None, 'error': "Loading... (JSON Error)"},
                                'wsl_storage': {'info': None, 'error': "Loading... (JSON Error)"}
                            }
                            safe_queue_put(data_queue, current_data)
                            continue
                        try:
                            ps_data = json.loads(json_str)
                            current_data = {
                                'host_cpu': ps_data.get('HostCpu', {'overall': None, 'per_core': None, 'error': 'No data from PS'}),
                                'host_processes': ps_data.get('HostProcesses', {'top_10': None, 'error': 'No data from PS'}),
                                'host_storage': ps_data.get('HostStorage', {'info': None, 'error': 'No data from PS'}),
                            }
                            try:
                                # Update WSL CPU data using local monitoring
                                wsl_cpu_percentages = wsl_cpu_monitor.get_cpu_percentages()
                                current_data['wsl_cpu'] = {'per_core': wsl_cpu_percentages, 'error': None}
                            except Exception as e:
                                current_data['wsl_cpu'] = {'per_core': None, 'error': str(e)}
                            wsl_storage_info, wsl_storage_err = get_wsl_storage_info()
                            current_data['wsl_storage'] = {'info': wsl_storage_info, 'error': wsl_storage_err}
                            safe_queue_put(data_queue, current_data)
                        except json.JSONDecodeError as e:
                            error_msg = f"JSON decode error from PowerShell: {e}. Raw: {json_str[:200]}..."
                            current_data = {
                                'host_cpu': {'overall': None, 'per_core': None, 'error': error_msg},
                                'host_processes': {'top_10': None, 'error': error_msg},
                                'host_storage': {'info': None, 'error': error_msg},
                                'wsl_cpu': {'per_core': None, 'error': "Loading... (JSON Error)"},
                                'wsl_storage': {'info': None, 'error': "Loading... (JSON Error)"}
                            }
                            safe_queue_put(data_queue, current_data)
            except BlockingIOError:
                pass
            except Exception as e:
                error_msg = f"Error reading from PowerShell stdout: {e}"
                current_data = {
                    'host_cpu': {'overall': None, 'per_core': None, 'error': error_msg},
                    'host_processes': {'top_10': None, 'error': error_msg},
                    'host_storage': {'info': None, 'error': error_msg},
                    'wsl_cpu': {'per_core': None, 'error': "Loading... (Read Error)"},
                    'wsl_storage': {'info': None, 'error': "Loading... (Read Error)"}
                }
                safe_queue_put(data_queue, current_data)
            exit_event.wait(0.1)
    except FileNotFoundError as e:
        current_data = {
            'host_cpu': {'overall': None, 'per_core': None, 'error': "PowerShell process terminated unexpectedly."},
            'host_processes': {'top_10': None, 'error': "PowerShell process terminated unexpectedly."},
            'host_storage': {'info': None, 'error': "PowerShell process terminated unexpectedly."},
            'wsl_cpu': {'per_core': None, 'error': "Loading... (PowerShell dead)"},
            'wsl_storage': {'info': None, 'error': "Loading... (PowerShell dead)"},
            'fatal': str(e)
        }
        safe_queue_put(data_queue, current_data)
    finally:
        if powershell_process and powershell_process.poll() is None:
            powershell_process.terminate()
            try:
                powershell_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
            if powershell_process.poll() is None:
                powershell_process.kill()
        if temp_script_path and os.path.exists(temp_script_path):
            os.remove(temp_script_path)


def main_loop(stdscr, data_queue, exit_event, update_interval):
    """
    Main display loop using curses. It polls data from the queue and draws the CPU and storage usage information
    for both Windows and WSL. Pressing 'q' will exit the loop.
    """
    curses.curs_set(0)
    stdscr.nodelay(True)
    last_drawn_data = {
        'host_cpu': {'overall': None, 'per_core': None, 'error': "Loading..."},
        'host_processes': {'top_10': None, 'error': "Loading..."},
        'host_storage': {'info': None, 'error': "Loading..."},
        'wsl_cpu': {'per_core': None, 'error': "Loading..."},
        'wsl_storage': {'info': None, 'error': "Loading..."}
    }
    base_time = time.monotonic()
    updated_time = time.strftime("%H:%M:%S")
    updating_spinner_index = 0
    heartbeat_spinner_index = 0
    while not exit_event.is_set():
        ch = stdscr.getch()
        if ch == ord('q'):
            exit_event.set()
            break
        try:
            while True:
                new_data = data_queue.get_nowait()
                updated_time = time.strftime("%H:%M:%S")
                last_drawn_data.update(new_data)
                if 'fatal' in last_drawn_data:
                    exit_event.set()
                    break
                updating_spinner_index += 1
        except queue.Empty:
            pass
        remaining_time = (base_time + update_interval * heartbeat_spinner_index) - time.monotonic()
        if remaining_time <= 0:
            heartbeat_spinner_index += 1
            if remaining_time < -update_interval:
                base_time = time.monotonic()
            stdscr.erase()
            line_index = 0
            updating_spinner_char = UPDATING_SPINNER_CHARS[updating_spinner_index % len(UPDATING_SPINNER_CHARS)]
            heartbeat_spinner_char = HEARTBEAT_SPINNER_CHARS[heartbeat_spinner_index % len(HEARTBEAT_SPINNER_CHARS)]
            safe_addstr(stdscr, line_index, 1, f"{heartbeat_spinner_char} WSL CPU Monitor - update time: {updated_time} {updating_spinner_char}")
            line_index += 1
            safe_addstr(stdscr, line_index, 0, "-" * DASH_LINE_LENGTH)
            line_index += 1
            safe_addstr(stdscr, line_index, 0, "Windows Host Per-Core CPU:")
            line_index += 1
            host_cpu_data = last_drawn_data.get('host_cpu', {})
            per_core, host_cpu_error = host_cpu_data.get('per_core'), host_cpu_data.get('error')
            if host_cpu_error:
                safe_addstr(stdscr, line_index, 0, f"Status: {host_cpu_error}")
                line_index += 2
            else:
                if per_core:
                    for core_info in per_core:
                        instance = core_info.get("Instance", "N/A")
                        usage = core_info.get("Value", 0.0)
                        safe_addstr(stdscr, line_index, 0, f"Core {instance}: {usage:6.2f}%  [{draw_progress_bar(usage, 30)}]")
                        line_index += 1
                else:
                    safe_addstr(stdscr, line_index, 0, "No per-core data.")
                    line_index += 1
            line_index += 1
            safe_addstr(stdscr, line_index, 0, "Windows Host Top 10 Processes (SMA):")
            line_index += 1
            host_proc_data = last_drawn_data.get('host_processes', {})
            proc_results, proc_error = host_proc_data.get('top_10'), host_proc_data.get('error')
            if proc_error:
                safe_addstr(stdscr, line_index, 0, f"Status: {proc_error}")
                line_index += 1
            elif proc_results:
                for proc_info in proc_results:
                    try:
                        pid = proc_info.get("Id", "N/A")
                        name = proc_info.get("ProcessName", "N/A")
                        cpu_usage = proc_info.get("CPU", 0.0)
                    except AttributeError:
                        pid = -1
                        name = "N/A"
                        cpu_usage = 0.0
                    safe_addstr(stdscr, line_index, 0, f"PID: {pid:<6}  Name: {name:<20}  {cpu_usage:6.2f}%")
                    line_index += 1
            else:
                safe_addstr(stdscr, line_index, 0, "No process data yet.")
                line_index += 1
            line_index += 1
            safe_addstr(stdscr, line_index, 0, "Windows Host Storage Usage (Drive C:):")
            line_index += 1
            host_storage_data = last_drawn_data.get('host_storage', {})
            storage_info, storage_error = host_storage_data.get('info'), host_storage_data.get('error')
            if storage_error:
                safe_addstr(stdscr, line_index, 0, f"Status: {storage_error}")
                line_index += 2
            else:
                if storage_info:
                    usage_percent, total, used, free = storage_info
                    bar_str = draw_progress_bar(usage_percent, 40)
                    safe_addstr(stdscr, line_index, 0, f"{usage_percent:6.2f}%  [{bar_str}]")
                    line_index += 2
                else:
                    safe_addstr(stdscr, line_index, 0, "No storage data yet.")
                    line_index += 2
            safe_addstr(stdscr, line_index, 0, "WSL2 Per-Core CPU:")
            line_index += 1
            wsl_cpu_data = last_drawn_data.get('wsl_cpu', {})
            wsl_per_core, wsl_cpu_error = wsl_cpu_data.get('per_core'), wsl_cpu_data.get('error')
            if wsl_cpu_error:
                safe_addstr(stdscr, line_index, 0, f"Status: {wsl_cpu_error}")
                line_index += 1
            else:
                if wsl_per_core:
                    for i, core in enumerate(wsl_per_core):
                        safe_addstr(stdscr, line_index, 0, f"Core {i}: {core:6.2f}%  [{draw_progress_bar(core, 30)}]")
                        line_index += 1
                else:
                    safe_addstr(stdscr, line_index, 0, "No WSL2 CPU data yet.")
                    line_index += 1
            line_index += 1
            safe_addstr(stdscr, line_index, 0, "WSL Storage Usage (/):")
            line_index += 1
            wsl_storage_data = last_drawn_data.get('wsl_storage', {})
            wsl_storage_info, wsl_storage_error = wsl_storage_data.get('info'), wsl_storage_data.get('error')
            if wsl_storage_error:
                safe_addstr(stdscr, line_index, 0, f"Status: {wsl_storage_error}")
                line_index += 2
            else:
                if wsl_storage_info:
                    usage_percent, size, used, available = wsl_storage_info
                    safe_addstr(stdscr, line_index, 0, f"{usage_percent:6.2f}%  (Size: {size}, Used: {used}, Avail: {available})")
                    line_index += 2
                else:
                    safe_addstr(stdscr, line_index, 0, "No WSL storage data yet.")
                    line_index += 2
            safe_addstr(stdscr, line_index + 1, 0, "Press 'q' to quit.")
            stdscr.refresh()
        else:
            time.sleep(remaining_time)
    if 'fatal' in last_drawn_data:
        res = last_drawn_data['fatal']
    else:
        res = None
    return res


def safe_addstr(win, y, x, text):
    """Wrapper for curses addstr with error handling to avoid curses errors."""
    try:
        win.addstr(y, x, text)
    except curses.error:
        pass


def parse_args():
    """Parse command-line arguments to allow dynamic configuration."""
    parser = argparse.ArgumentParser(description="WSL and Windows Host CPU/Storage Monitor")
    parser.add_argument('--powershell-path', type=str, default=DEFAULT_POWERSHELL_PATH,
                        help="Path to the Windows PowerShell executable")
    parser.add_argument('--temp_dir', type=str, default=DEFAULT_TEMP_DIR,
                        help="WSL path for the Windows temporary directory")
    parser.add_argument('--update_interval', type=float, default=DEFAULT_UPDATE_INTERVAL,
                        help="Screen update interval in seconds")
    # Optional: allow overriding encoding as well
    parser.add_argument('--powershell_encoding', type=str, default=POWERSHELL_ENCODING,
                        help="Encoding used for PowerShell output")
    return parser.parse_args()


def main():
    """Main function to initialize configuration and start the monitoring threads."""
    args = parse_args()
    config = {
        "powershell_path": args.powershell_path,
        "temp_dir": args.temp_dir,
        "update_interval": args.update_interval,
        "powershell_encoding": args.powershell_encoding
    }
    data_queue = queue.Queue(maxsize=10)
    exit_event = threading.Event()
    collector_thread = threading.Thread(target=data_collector_process, args=(data_queue, exit_event, config), daemon=True)
    collector_thread.start()
    res = curses.wrapper(lambda stdscr: main_loop(stdscr, data_queue, exit_event, config["update_interval"]))
    if res:
        print(res)
    exit_event.set()
    collector_thread.join(timeout=5)


if __name__ == '__main__':
    main()

