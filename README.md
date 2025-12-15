# WebShell Monitor & Scanner

![Bash Shell](https://img.shields.io/badge/Shell-Bash-4EAA25?style=flat&logo=gnu-bash&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-blue)
![License](https://img.shields.io/badge/License-MIT-green)

A lightweight, heuristic-based security scanner written in Bash. It detects potential **WebShells**, **Backdoors**, and **Suspicious PHP Scripts** on Linux servers.

Designed for performance and compatibility, it runs smoothly on older systems (CentOS 7) as well as modern distributions (Ubuntu 20.04+, Debian), using memory-efficient file streaming.

## 🚀 Features

* **Smart Heuristics:** Detects `eval`, `base64_decode`, obfuscated code, hex-encoding, and suspicious variable functions.
* **Interactive Menu:** Easy-to-use CLI panel for manual scanning.
* **Performance Optimized:** Uses stream processing (`find | while read`) to handle thousands of files without high RAM usage.
* **Two Scan Modes:**
    * **Fast:** Scans only `.php` files (Recommended for production).
    * **Deep:** Scans all text-based files (Slower, thorough).
* **False Positive Reduction:** Whitelists common CMS directories (`vendor`, `node_modules`, `wp-includes`).
* **Automation Ready:** Can be used with Cron jobs via command-line arguments.

## 📥 Installation

```bash
git clone [https://github.com/yasinkuyu/monitor.sh.git](https://github.com/yasinkuyu/monitor.sh.git)
cd monitor.sh
chmod +x monitor.sh
