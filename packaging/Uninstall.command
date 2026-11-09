#!/bin/zsh
# Informational: uninstall must leave private settings, trust and migration backups alone.
open -a Finder "$HOME/Applications"
printf '%s\n' 'Quit Corporate VPN Router from its menu. In Finder move its app to Trash. Remove com.geokhv.corporate-vpn-router.menu.plist from your own Library/LaunchAgents. Keep the Application Support directory for rollback.'
