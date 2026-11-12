"""Bind a previously confirmed official CA to the configured site and its IP.
Candidate certificates are public discovery data. No CCC or credentials are
sent until a separate authenticated connection succeeds."""
import hashlib, ipaddress, json, os, re, socket, ssl, stat, subprocess, tempfile
from pathlib import Path
from tls_policy import pinned_context

CP = Path('/Library/Application Support/Checkpoint/Endpoint Connect')
DATA = Path.home() / 'Library/Application Support/Corporate VPN Router'
APPROVED_GATEWAY = DATA/'Provisioning/ApprovedGateway.json'
if not APPROVED_GATEWAY.exists():
    APPROVED_GATEWAY = Path(__file__).resolve().parent.parent/'ApprovedGateway.json'
class Refused(RuntimeError): pass

def preapproved(receipt):
    """A private build may pin the already verified colleague configuration.

    This is an additional exact SHA-256/site/IP/CN check, never a substitute
    for the signed official client, its accepted fingerprint, or live TLS.
    Generic builds without this manifest keep their explicit approval flow.
    """
    if not APPROVED_GATEWAY.exists():return False
    try:
        value=json.loads(APPROVED_GATEWAY.read_text())
        expected=value['receipt']
        valid=(value['schema']==1 and value['automaticFirstUse'] is True
            and value['provenance']=='OWNER_APPROVED_EXISTING_OFFICIAL_CLIENT_PIN_AND_STRICT_LIVE_TLS'
            and set(expected)=={'site','ip','cn','ca_sha256'}
            and all(isinstance(v,str) and v for v in expected.values())
            and re.fullmatch('[0-9a-f]{64}',expected['ca_sha256']))
        if not valid:raise ValueError()
    except (ValueError,KeyError,TypeError,OSError):raise Refused('APPROVED_GATEWAY_INVALID') from None
    if expected!=receipt:raise Refused('APPROVED_GATEWAY_MISMATCH')
    return True

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
    try:
        p=subprocess.run([str(trac),'info'],capture_output=True,timeout=10)
    except subprocess.TimeoutExpired:
        raise Refused('OFFICIAL_INFO_TIMEOUT') from None
    output=p.stdout.decode(errors='replace')
    service_output=(output+'\n'+p.stderr.decode(errors='replace')).lower()
    if any(marker in service_output for marker in ('service is not started', 'vpn service is down',
            'connectivity with the check point endpoint security service is lost')):
        raise Refused('OFFICIAL_SERVICE_NOT_STARTED')
    if p.returncode: raise Refused('OFFICIAL_INFO_FAILED')
    sites=re.findall(r'^Conn ([a-zA-Z0-9.-]+):\s*\n\s*gw: ([0-9.]+)\s*$',output,re.M)
    headers=re.findall(r'^Conn .*:',output,re.M)
    if len(headers)>1 or len(sites)>1: raise Refused('OFFICIAL_SITE_AMBIGUOUS')
    if not sites:
        raise Refused('OFFICIAL_SITE_FORMAT_UNSUPPORTED' if headers else 'OFFICIAL_SITE_MISSING')
    statuses=re.findall(r'^\s*status:\s*([^\r\n]+)',output,re.M)
    if len(statuses)!=1: raise Refused('OFFICIAL_STATE_UNKNOWN')
    host,ip=sites[0]; ip=str(ipaddress.IPv4Address(ip))
    return host.lower(),ip,statuses[0].strip()

def site(require_idle=True):
    host,ip,state=official_info()
    if require_idle and state!='Idle': raise Refused('OFFICIAL_VPN_NOT_IDLE')
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

def anchor(approve, require_idle=True, resilient=False):
    host,ip=site() if require_idle else site(require_idle=False)
    # Certificate inventory only: stdin is EOF and no application data is sent.
    command=['/usr/bin/openssl','s_client','-connect',ip+':443','-servername',host,'-showcerts']
    if resilient:
        from connection_resilience import discover
        p=discover(command,timeout=12)
    else:
        p=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,timeout=12)
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
        connector=socket.create_connection
        if resilient:
            from connection_resilience import connect
            connector=connect
        with connector((ip,443),timeout=10) as raw,ctx.wrap_socket(raw,server_hostname=ip) as tls:
            if tls.getpeercert(binary_form=True)!=ssl.PEM_cert_to_DER_cert(chain[0].decode()): raise Refused('GATEWAY_CHANGED')
    receipt={'site':host,'ip':ip,'cn':names[0],'ca_sha256':digest}
    already_verified=preapproved(receipt)
    path=DATA/'ssl-site.json'
    if path.exists():
        if json.loads(path.read_text())!=receipt: raise Refused('SAVED_SITE_OR_PIN_CHANGED')
    else:
        if not already_verified:approve(receipt)
        with path.open('x') as f: json.dump(receipt,f)
    return ip,ctx
