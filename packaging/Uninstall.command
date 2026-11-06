#!/bin/zsh
set -eu
DIR="${0:A:h}"
"$DIR/Corporate VPN Router.app/Contents/MacOS/CorporateVPNRouter" --uninstall
printf '%s\n' 'Private settings kept. To remove them too, use --uninstall --purge as described in the guide.'
