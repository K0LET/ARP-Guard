# 🛡️ Arp-Guard

## This project is my twelfth-grade cyber project. This code is for learning purposes only

**Arp-Guard** is a cross-platform system designed for ARP spoofing detection and protection. It consists of both Linux and Windows components, including kernel-level drivers and user assets. the linux driver is working, but the windows isn't.

---

## 📁 Project Structure
Arp-Guard/<br>
├── linux/ # Linux-specific files<br>
│ ├── assets/ # Static resources<br>
│ └── driver/ # Linux kernel driver and Makefile<br>
├── windows/ # Windows-specific files<br>
│ ├── assets/ # Static resources<br>
│ └── driver/ # Windows driver source<br>
Arp-Spoofer/<br>
└── assets/ # Related assets for spoofing tools<be>


## 🐧 Linux Driver

### Build Requirements

Ensure you have the following installed:

```bash
sudo apt update
sudo apt install build-essential linux-headers-$(uname -r)
```

You can see further instructions in the linux/driver readme file 

📦 Arp-Spoofer
A module containing assets used in testing or spoofing tools, useful for validating detection systems in Arp-Guard.

⚠️ Disclaimer
This project is intended for *educational* and *research* purposes only. Do not deploy or run these drivers on machines you do not own or control.
