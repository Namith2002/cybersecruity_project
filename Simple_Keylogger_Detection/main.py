import os
import psutil
import win32api
import win32con
import win32process

def get_process_info():
    """
    Retrieve all running processes and their executable paths.
    """
    process_list = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            process_list.append({
                'pid': proc.info['pid'],
                'name': proc.info['name']
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return process_list


def detect_keylogger():
    """
    Scan for processes that might act like keyloggers based on suspicious behaviors.
    """
    suspicious_processes = []
    process_list = get_process_info()

    print("Scanning active processes...\n")
    for process in process_list:
        try:
            pid = process['pid']
            name = process['name']

            # Get the executable path of the process
            handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, pid)
            _, exe_path = win32process.GetModuleFileNameEx(handle, 0)
            
            # Check for suspicious indicators
            if "keylogger" in name.lower() or "hook" in name.lower() or "keyboard" in name.lower():
                suspicious_processes.append((name, exe_path))

            win32api.CloseHandle(handle)
        except Exception as e:
            # Handle processes that cannot be accessed
            pass

    if suspicious_processes:
        print("\nPotential keylogger detected!")
        for name, exe_path in suspicious_processes:
            print(f"- Process Name: {name}")
            print(f"  Executable Path: {exe_path}")
            print("  Recommendation: Inspect or terminate the process.\n")
    else:
        print("No keyloggers detected. Your system appears safe.\n")


def mitigation_tips():
    """
    Provide tips to mitigate keylogger threats.
    """
    print("\nMitigation Tips:")
    print("- Update your antivirus and run a full system scan.")
    print("- Inspect startup programs for unknown entries.")
    print("- Use a firewall to monitor outbound connections.")
    print("- Avoid downloading unknown software from untrusted sources.")
    print("- Consider using a virtual keyboard for sensitive inputs.")


def main():
    print("Simple Keylogger Detection Tool")
    print("-" * 40)

    detect_keylogger()
    mitigation_tips()


if __name__ == "__main__":
    main()
