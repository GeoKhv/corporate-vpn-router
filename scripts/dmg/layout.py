#!/usr/bin/env python3
"""Write portable DMG view metadata directly; never automate Finder."""
import sys
from pathlib import Path
from metadata import DSStore, Alias, Bookmark
from mac_alias.bookmark import kBookmarkVolumePath, kBookmarkVolumeURL, URL

root = Path(sys.argv[1])
background = str(root/'.background/background.png')
volume_path = '/Volumes/Corporate VPN Router beta.6'
alias = Alias.for_file(background)
alias.volume.posix_path = volume_path.encode()
bookmark = Bookmark.for_file(background)
for _, toc in bookmark.tocs:
    toc[kBookmarkVolumePath] = volume_path
    toc[kBookmarkVolumeURL] = URL('file://' + volume_path)

with DSStore.open(str(root/'.DS_Store'), 'w+') as store:
    store['.']['vSrn'] = ('long', 1)
    store['.']['icvl'] = ('type', b'icnv')
    store['.']['bwsp'] = {
        'ShowStatusBar': False, 'WindowBounds': '{{100, 100}, {860, 552}}',
        'ContainerShowSidebar': False, 'PreviewPaneVisibility': False,
        'SidebarWidth': 0, 'ShowTabView': False, 'ShowToolbar': False,
        'ShowPathbar': False, 'ShowSidebar': False,
    }
    store['.']['icvp'] = {
        'viewOptionsVersion': 1, 'backgroundType': 2,
        'backgroundImageAlias': alias.to_bytes(),
        'backgroundColorRed': 1.0, 'backgroundColorGreen': 1.0, 'backgroundColorBlue': 1.0,
        'gridOffsetX': 0.0, 'gridOffsetY': 0.0, 'gridSpacing': 100.0,
        'arrangeBy': 'none', 'showIconPreview': False, 'showItemInfo': False,
        'labelOnBottom': True, 'textSize': 14.0, 'iconSize': 112.0,
        'scrollPositionX': 0.0, 'scrollPositionY': 0.0,
    }
    store['.']['pBBk'] = bookmark
    store['Установить Corporate VPN Router.app']['Iloc'] = (425, 255)
    store['Установка и откат.txt']['Iloc'] = (740, 90)
