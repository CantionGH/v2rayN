#!/bin/bash -p
set -euo pipefail
[[ "$EUID" == 0 ]] || { echo 'Administrator authorization is required.' >&2; exit 1; }
if /bin/launchctl print system/2dust.v2rayN.LocalTunHelper >/dev/null 2>&1; then
  /bin/launchctl bootout system/2dust.v2rayN.LocalTunHelper
fi
# Fixed files only. Keep the app, user profiles and logs; do not recursively
# delete an application/data directory from a privileged shell script.
/bin/rm -f '/Library/LaunchDaemons/2dust.v2rayN.LocalTunHelper.plist' \
  '/Library/Application Support/v2rayN-LocalTun/trust.plist'
echo 'Local TUN privilege revoked. User configuration and the installed app were not deleted.'
