# Python-Nmap Vulnerability Scanner

This project leverages the powerful capabilities of Nmap through Python integration (`python-nmap`) to perform automated network scans and identify potential vulnerabilities, extracting CVEs when available.

## 🚀 Features

* **Automated scanning** of IP addresses, IP ranges, and domains.
* Extracts detailed service information including version and OS.
* Identifies potential vulnerabilities via CVE extraction.
* Generates structured reports:

  * JSON format (`scan_results.json`)
  * User-friendly HTML summary (`scan_summary.html`)

## 📌 Requirements

* Python 3.x
* [Nmap](https://nmap.org/download.html)
* Python-Nmap module (`python-nmap`)

## ⚙️ Installation

### 1. Install Nmap

* [Nmap official download page](https://nmap.org/download.html)

### 2. Clone Repository

```bash
git clone https://github.com/Mrjaiswal108/nmap_Automation.git
cd nmap_Automation
```

### 3. Install Dependencies

```bash
pip install python-nmap
```

## 🚦 Usage

Run the script:

```bash
python main.py
```

### Example

```
Enter RHOSTS seperated by (comma[,] or space[ ]): 45.33.32.156
Enter Arguments or press ENTER:

Scanning...........
[*]Scanning Host:45.33.32.156

[*]Protocol :tcp  Port :22  Service Running :OpenSSH  version :7.2p2  OS :Linux  CVE Found :['CVE-2016-10009']  state:up

[+] Finished scanning ['45.33.32.156'], found 1 service entries.
```

## 📄 Reports

After scanning completes, you will find two files generated in your directory:

* `scan_results.json`: Contains detailed structured output.
* `scan_summary.html`: Easy-to-read summary.

Open `scan_summary.html` in any web browser to review results visually.

## ⚠️ Disclaimer

**Only use this tool on systems where you have explicit permission to conduct security assessments.** Unauthorized scanning can lead to legal consequences.

## 📚 License

This project is open-source, licensed under the MIT License.
