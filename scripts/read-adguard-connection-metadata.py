#!/usr/bin/env python3
"""User-mediated, one-file access; export fixed network metadata only.

Never write or print the source log, exception text, URLs, request bodies,
account identifiers or authorization material. The macOS chooser is operated
by the owner; this script does not change TCC, permissions or AdGuard settings.
"""
import argparse
import datetime
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys

STAMP = re.compile(r'\b(?:20\d\d[-/]\d\d[-/]\d\d[T ]+)?\d\d:\d\d:\d\d(?:[.,]\d{1,6})?(?:Z|[+-]\d\d:?\d\d)?\b')
NETWORK_ENDPOINT = re.compile(r'\b(?:destination|remote|proxy|server|local|peer|source)(?:[_ ](?:address|endpoint|addr))?\s*[=:]\s*["\[]?((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?', re.I)
ERRNO = re.compile(r'\b(?:errno|os_error)\s*[=:]\s*(-?\d{1,4})\b', re.I)
MARKERS = ('ECONNREFUSED','ETIMEDOUT','EHOSTUNREACH','ENETUNREACH','ConnectionRefusedError',
           'TimeoutError','SYN_SENT','ESTABLISHED','connection refused','connection timed out',
           'connect failed','connect_failed','timed out','timeout')


def extract(text, target):
    target = str(ipaddress.IPv4Address(target))
    rows = []
    for line in text.splitlines():
        # Keep only rows naming this destination; do not export other domains.
        if not re.search(r'(?<![0-9.])'+re.escape(target)+r'(?![0-9.])',line):
            continue
        stamps = STAMP.findall(line)
        markers = [m for m in MARKERS if m.lower() in line.lower()]
        endpoints = []
        for address, port in NETWORK_ENDPOINT.findall(line):
            try:
                ip = str(ipaddress.IPv4Address(address))
                number = int(port) if port else None
                if number is not None and not 0 <= number <= 65535:continue
                endpoints.append({'ip':ip,'port':number})
            except ValueError:pass
        rows.append({'timestamp_tokens':stamps[:2], 'target':target,
                     'markers':markers, 'labelled_endpoint_tokens':endpoints[:8],
                     'errno_tokens':[int(n) for n in ERRNO.findall(line)[:4]]})
        if len(rows) >= 2000:break
    return rows


def select_and_read():
    expected = Path.home()/'Library/Group Containers/TC3Q7MAJXF.com.adguard.mac/Library/Logs/com.adguard.mac.vpn/AdGuard VPN-group.log'
    # All arguments are passed as argv, never interpolated into AppleScript.
    script = '''on run argv
set expectedPath to item 1 of argv
set chosenFile to choose file with prompt "Router: выберите только AdGuard VPN-group.log. Будут сохранены лишь время, IP и транспортные ошибки; полный журнал не сохраняется." default location (POSIX file (item 2 of argv))
if (POSIX path of chosenFile) is not expectedPath then error "WRONG_FILE" number 2001
set handle to open for access chosenFile
try
    set byteCount to get eof handle
    if byteCount > 4194304 then
        set firstByte to byteCount - 4194304 + 1
        set byteCount to 4194304
    else
        set firstByte to 1
    end if
    if byteCount is 0 then
        set resultText to ""
    else
        set resultText to read handle from firstByte for byteCount as «class utf8»
    end if
    close access handle
    return resultText
on error
    try
        close access handle
    end try
    error "READ_DENIED" number 2002
end try
end run'''
    result = subprocess.run(['/usr/bin/osascript','-',str(expected),str(expected.parent)],
                            input=script.encode(),capture_output=True,timeout=180)
    if result.returncode:
        # stderr can include paths or dynamic text. It is deliberately discarded.
        return None, 'SELECTION_CANCELLED_OR_READ_DENIED'
    return result.stdout.decode('utf-8',errors='replace'), None


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--gateway',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    target=str(ipaddress.IPv4Address(args.gateway))
    if args.output.exists():raise SystemExit('OUTPUT_EXISTS')
    try: text,error=select_and_read()
    except subprocess.TimeoutExpired:text,error=None,'SELECTION_TIMEOUT'
    rows=extract(text,target) if text is not None else []
    del text
    report={'schema':1,'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'status':error or 'READ_SUCCEEDED','gateway':target,'events':rows,
            'limitations':['Only the last 4 MiB were examined in memory; source log was not saved.',
                'Markers are literal tokens, not a verdict that an error occurred.',
                'No match does not prove absence of a flow or error.']}
    import os
    fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as out:json.dump(report,out,indent=2)
    print(json.dumps({'status':report['status'],'matched_rows':len(rows),'report':str(args.output)}))


if __name__=='__main__':main()
