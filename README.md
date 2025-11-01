# Ghidorah 🐲
Automated web reconnaissance and bug bounty toolkit with Tor IP rotation for enhanced anonymity and bypassing IP-based restrictions.

Features
Subdomain Discovery: Comprehensive enumeration using multiple tools

Content Crawling: JavaScript analysis and endpoint discovery

Directory Fuzzing: Path discovery with Tor IP rotation

Vulnerability Scanning: Nuclei integration with automated testing

IP Rotation: Automatic Tor circuit rotation to evade detection

Quick Start
bash
./ghidorah.sh example.com all
Usage
bash
./ghidorah.sh <domain> [subs|crawl|pfuzz|afuzz|vuln|all]
Options
subs - Subdomain discovery only

crawl - Content crawling and JavaScript analysis

pfuzz - Passive URL fuzzing with urlfinder

afuzz - Active directory fuzzing with Tor rotation

vuln - Vulnerability scanning with Nuclei

all - Complete reconnaissance pipeline

Dependencies
Requires: urlfinder, assetfinder, subfinder, httpx, gau, katana, uro, ffuf, jq, cowsay, nuclei, notify

Legal
For authorized security testing only. Use only on targets you own or have explicit permission to test.

Use responsibly and respect all applicable laws.
