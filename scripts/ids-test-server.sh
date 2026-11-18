#!/usr/bin/env bash
# Safe IDS test: serve fake "id" command output so ET/GPL ATTACK_RESPONSE rules fire.
# Run on Kali, then from the attacker machine: curl http://192.168.64.10:8000/id.txt
# Expected alerts: SID 2100498 (GPL ATTACK_RESPONSE id check returned root), SID 2019284
# Stop with Ctrl+C when done (do not leave the port open).
set -e
mkdir -p ~/lab2/nids-test && cd ~/lab2/nids-test
echo 'uid=0(root) gid=0(root) groups=0(root)' > id.txt
python3 -m http.server 8000
