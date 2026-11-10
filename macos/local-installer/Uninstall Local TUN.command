#!/bin/bash
set -euo pipefail
# The command is constant: no caller-controlled path/argument enters a root shell.
/usr/bin/osascript <<'APPLESCRIPT'
do shell script "/bin/bash -p '/Library/Application Support/v2rayN-LocalTun/v2rayN.app/Contents/Resources/LocalTun/uninstall.sh'" with administrator privileges
APPLESCRIPT
