# Advanced Vulnerability Assessment Tool

A comprehensive web application security scanner that combines features from LostXtools and loxs to provide thorough vulnerability assessment capabilities.

## Features

- **Vulnerability Scanning**
  - Cross-Site Scripting (XSS)
  - SQL Injection (SQLi)
  - Local File Inclusion (LFI)
  - Open Redirect
  - WordPress Vulnerabilities
  - SSL/TLS Security
  - DNS Security
  - Port Scanning
  - Web Security Headers

- **Advanced Capabilities**
  - Multi-threaded scanning
  - Selenium-based dynamic testing
  - Shodan integration
  - Comprehensive PDF reporting
  - WordPress plugin analysis
  - Real-time vulnerability detection

## Prerequisites

- Python 3.x
- Google Chrome
- ChromeDriver

### Required Python Packages
```bash
aiohttp>=3.8.6
beautifulsoup4>=4.11.2
colorama>=0.3.9
fake_useragent>=1.2.1
requests>=2.32.3
rich>=13.8.1
selenium
python-nmap
shodan
dnspython
pyOpenSSL
python-whois
reportlab
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Likhithsai2580/bug_bounty_automation_2.0.git
cd advanced-vulnerability-scanner
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Install Chrome and ChromeDriver:

For Debian/Ubuntu:
```bash
# Install Chrome
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo dpkg -i google-chrome-stable_current_amd64.deb
sudo apt -f install

# Install ChromeDriver
wget https://storage.googleapis.com/chrome-for-testing-public/128.0.6613.119/linux64/chromedriver-linux64.zip
unzip chromedriver-linux64.zip
sudo mv chromedriver-linux64/chromedriver /usr/bin/
```

## Usage

Basic usage:
```bash
python advanced_vulnerability_assesment.py -t example.com
```

With all options:
```bash
python advanced_vulnerability_assesment.py -t example.com -k YOUR_SHODAN_API_KEY -o report.pdf --threads 10
```

### Command Line Arguments

- `-t, --target`: Target domain or IP address (required)
- `-k, --shodan-key`: Shodan API key for additional reconnaissance
- `-o, --output`: Output PDF file path (default: vulnerability_report.pdf)
- `--threads`: Number of concurrent threads (default: 5)

## Output

The tool generates a detailed PDF report containing:
- Target information
- Scan timestamp
- Discovered vulnerabilities with severity levels
- Technical details of findings
- Recommendations for remediation

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This tool is for educational purposes and authorized testing only. Always obtain proper authorization before scanning any systems or networks. The authors are not responsible for any misuse or damage caused by this tool.

## Credits

This tool combines and enhances features from:
- LostXtools
- loxs
- Various open-source security tools and libraries

## License

MIT License - See LICENSE file for details 
