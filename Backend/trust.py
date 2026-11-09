"""Bind a previously confirmed official CA to the configured site and its IP.
Candidate certificates are public discovery data. No CCC or credentials are
sent until a separate authenticated connection succeeds."""
import hashlib, ipaddress, json, os, re, socket, ssl, stat, subprocess, tempfile
from pathlib import Path
from tls_policy import pinned_context

CP = Path('/Library/Application Support/Checkpoint/Endpoint Connect')
DATA = Path.home() / 'Library/Application Support/Corporate VPN Router'
class Refused(RuntimeError): pass

def owned(path):
    st=path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise Refused('UNTRUSTED_OFFICIAL_FILE')
    for parent in path.parents:
        st=parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise Refused('UNTRUSTED_OFFICIAL_DIRECTORY')

def official_info():
    trac=CP/'trac'
    owned(trac)
    vendor='anchor apple generic and certificate leaf[subject.OU] = "TZ3UEPFYKD" and identifier "trac"'
    verification=subprocess.run(['/usr/bin/codesign','--verify','--strict','-R='+vendor,str(trac)],
        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=12)
    if verification.returncode: raise Refused('OFFICIAL_SIGNATURE_INVALID')
    p=subprocess.run([str(trac),'info'],capture_output=True,timeout=10)
    sites=re.findall(r'^Conn ([a-zA-Z0-9.-]+):\s*\n\s*gw: ([0-9.]+)\s*$',p.stdout.decode(errors='replace'),re.M)
    if p.returncode or len(sites)!=1: raise Refused('OFFICIAL_SITE_AMBIGUOUS')
    statuses=re.findall(r'^\s*status:\s*([^\r\n]+)',p.stdout.decode(errors='replace'),re.M)
    if len(statuses)!=1: raise Refused('OFFICIAL_STATE_UNKNOWN')
    host,ip=sites[0]; ip=str(ipaddress.IPv4Address(ip))
    return host.lower(),ip,statuses[0].strip()

def site():
    host,ip,state=official_info()
    if state!='Idle': raise Refused('OFFICIAL_VPN_NOT_IDLE')
    if ip not in {r[4][0] for r in socket.getaddrinfo(host,443,socket.AF_INET,socket.SOCK_STREAM)}:
        raise Refused('SITE_ADDRESS_MISMATCH')
    return host.lower(),ip

def fingerprint(der):
    words=Path(__file__).with_name('words.txt').read_text().split()
    bits=''.join(f'{x:08b}' for x in hashlib.sha1(der).digest()[:16])
    result=[]
    for start in [0,64]:
        block=bits[start:start+64]
        checksum=sum(int(block[i:i+2],2) for i in range(0,64,2)) % 4
        block+=f'{checksum:02b}'
        result.extend(words[int(block[i:i+11],2)] for i in range(0,66,11))
    return ' '.join(result)

def accepted(cn,words):
    reg=CP/'registry/HKLM_registry.data'
    owned(reg)
    s=reg.read_text()
    matches=list(re.finditer(r'(?m)^(\s*): \(accepted_cn[ \t]*$',s))
    if len(matches)!=1: raise Refused('OFFICIAL_PIN_MISSING')
    m=matches[0]; indent=m[1].split('\n')[-1]
    section=s[m.end():].split('\n'+indent+')',1)[0]
    entries=re.findall(r':\s*\("([^"\n]+)"\s*:--Fingerprint--\s*\("([A-Z ]+)"\)\s*\)',section)
    if entries!=[(cn,words)]: raise Refused('OFFICIAL_PIN_MISMATCH')

def anchor(approve):
    host,ip=site()
    # Certificate inventory only: stdin is EOF and no application data is sent.
    p=subprocess.run(['/usr/bin/openssl','s_client','-connect',ip+':443','-servername',host,'-showcerts'],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=12)
    chain=re.findall(rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',p.stdout,re.S)
    if not 2<=len(chain)<=8: raise Refused('GATEWAY_CHAIN_INCOMPLETE')
    with tempfile.TemporaryDirectory() as d:
        leaf=Path(d)/'leaf'; leaf.write_bytes(chain[0])
        decoded=ssl._ssl._test_decode_cert(str(leaf))
        names=[v for group in decoded['subject'] for k,v in group if k=='commonName']
        if len(names)!=1 or ('IP Address',ip) not in decoded['subjectAltName']: raise Refused('SITE_SAN_MISMATCH')
        der=ssl.PEM_cert_to_DER_cert(chain[-1].decode())
        accepted(names[0],fingerprint(der))
        digest=hashlib.sha256(der).hexdigest()
        ca=Path(d)/'ca';ca.write_bytes(chain[-1])
        ctx=pinned_context(ca,digest)
        with socket.create_connection((ip,443),timeout=10) as raw,ctx.wrap_socket(raw,server_hostname=ip) as tls:
            if tls.getpeercert(binary_form=True)!=ssl.PEM_cert_to_DER_cert(chain[0].decode()): raise Refused('GATEWAY_CHANGED')
    receipt={'site':host,'ip':ip,'cn':names[0],'ca_sha256':digest}
    path=DATA/'ssl-site.json'
    if path.exists():
        if json.loads(path.read_text())!=receipt: raise Refused('SAVED_SITE_OR_PIN_CHANGED')
    else:
        approve(receipt)
        with path.open('x') as f: json.dump(receipt,f)
    return ip,ctx
