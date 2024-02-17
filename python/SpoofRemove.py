from ctypes import *
import sys
import subprocess


def run_as_admin(command="arp -d"):
    try:
        if sys.platform == 'win32':
            # Trigger UAC elevation
            windll.shell32.ShellExecuteW(None, "runas", "cmd.exe", f"/C {command} && exit", None, 1)
        else:
            raise RuntimeError("Unsupported platform")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def run_cmd(command):
    try:
        if sys.platform == 'win32':
            subprocess.run(f"start cmd /K {command}", shell=True)
        else:
            raise RuntimeError("Unsupported platform")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    # windll.shell32.ShellExecuteW(None, "runas", "cmd.exe", f"/D {command}", None, 1)
    # with os.popen("arp -a") as f:
    #     data = f.read()
    # _dict = {}
    # for line in re.findall('([-.0-9]+)\s+([-0-9a-f]{17})', data):
    #     _dict[line[0]] = line[1]
    # return _dict

# Example: Run a command that requires elevation

#
# command_to_run = "arp -d"
# run_as_admin(command_to_run)

# k = windll.kernel32
# print(k)

#TODO: option 1