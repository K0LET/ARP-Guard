# Linux Kernel Driver for Arp-Guard

This project contains a Linux kernel module used as part of the Arp-Guard system. The driver can be built and loaded into the kernel for development or testing purposes.

## 📁 Project Structure

Arp-Guard/
├── linux/<br>
│ ├── assets/ # Static files/resources<br>
│ └── driver/ # Linux driver source and Makefile<br>

## 🛠 Requirements

Before building the driver, make sure you have the necessary development tools installed:

```bash
sudo apt update
sudo apt install build-essential linux-headers-$(uname -r)
```

🧱 Build Instructions
1. Navigate to the Linux driver source directory:
```bash
cd Arp-Guard/linux/driver
```

2. build the driver:
```bash
make
```

🚀 Load the Driver
Insert the kernel module:
```bash
sudo insmod my_driver.ko
```

Verify it is loaded:
```bash
lsmod | grep my_driver
dmesg | tail
```

❌ Unload the Driver
To remove the module:
```bash
sudo rmmod my_driver
```

Check the kernel log:
```bash
dmesg | tail
```

🧹 Clean Up
```bash
make clean
```


⚠️ Disclaimer
This driver is intended for educational, testing, or research purposes. Use it responsibly and only on systems where you have permission to load kernel modules.
