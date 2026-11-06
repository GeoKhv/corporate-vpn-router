#!/bin/zsh
set -eu
DIR="${0:A:h}"
"$DIR/Corporate VPN Router.app/Contents/MacOS/CorporateVPNRouter" --install
open "$HOME/Applications/Corporate VPN Router.app"
