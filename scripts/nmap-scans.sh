#!/usr/bin/env bash
# Reconnaissance scans run from the attacker (Mac) against the lab target only.
# Only scan systems you own or are authorised to test.
TARGET="${1:-192.168.64.10}"
sudo nmap -sS "$TARGET"                       # SYN (half-open) scan, top 1000 ports
sudo nmap -sV -sC -p 22,8000 "$TARGET"        # service/version + default NSE scripts
sudo nmap -O "$TARGET"                        # OS fingerprinting
sudo nmap -sS -sV -sC -O "$TARGET"            # combined scan used to test Wazuh rules
