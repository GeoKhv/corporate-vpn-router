"""Bind a previously confirmed official CA to the configured DNS site or legacy IP.
Candidate certificates are public discovery data. No CCC or credentials are
sent until a separate authenticated connection succeeds."""
import hashlib, ipaddress, json, os, re, socket, ssl, stat, subprocess, tempfile
import threading
import time
from concurrent.futures import Future, TimeoutError as FutureTimeout
from pathlib import Path
from tls_policy import pinned_context, pin_gateway_leaf

CP = Path('/Library/Application Support/Checkpoint/Endpoint Connect')
DATA = Path.home() / 'Library/Application Support/Corporate VPN Router'
APPROVED_GATEWAY = DATA/'Provisioning/ApprovedGateway.json'
if not APPROVED_GATEWAY.exists():
    APPROVED_GATEWAY = Path(__file__).resolve().parent.parent/'ApprovedGateway.json'
class Refused(RuntimeError): pass


def binding_matches(saved, verified):
    if saved == verified:
        return True
    # A 0.3.8 object enrollment already verified these exact certificates.
    if (isinstance(saved,dict) and set(verified)=={'site','cn','ca_sha256','leaf_sha256'}
            and set(saved)==set(verified)|{'gateway_object'}):
        return all(saved[k]==v for k,v in verified.items())
    # Older receipts and the starter manifest recorded an IP. Only a fresh
    # authenticated DNS identity permits disregarding that historic address.
    if not isinstance(saved, dict) or 'ip' not in saved or 'dns_name' not in verified:
        return False
    return (verified['dns_name'] == verified['site'] and
            {k:v for k,v in saved.items() if k != 'ip'} ==
            {k:v for k,v in verified.items() if k != 'dns_name'})

def approved_receipt():
    """A private build may pin the already verified colleague configuration.

    This is an additional exact SHA-256/site/IP/CN check, never a substitute
    for the signed official client, its accepted fingerprint, or live TLS.
    Generic builds without this manifest keep their explicit approval flow.
    """
    if not APPROVED_GATEWAY.exists():return None
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
    return expected

def read_site_pin(path):
    from sites import hostname
    try:
        pin=json.loads(path.read_text())
        if (not isinstance(pin,dict) or set(pin)!={'schema','site','leaf_sha256','ca_sha256'}
                or type(pin['schema']) is not int or pin['schema']!=1 or not hostname(pin['site'])
                or not all(isinstance(pin[k],str) and re.fullmatch('[0-9a-f]{64}',pin[k])
                           for k in ('leaf_sha256','ca_sha256'))):
            raise ValueError()
    except (ValueError,TypeError,OSError):
        raise Refused('APPROVED_GATEWAY_INVALID') from None
    return pin


def approved_site_pin():
    stored=DATA/'Provisioning/ApprovedSitePin.json'
    bundled=Path(__file__).resolve().parent.parent/'ApprovedSitePin.json'
    pins=[read_site_pin(path) for path in (bundled,stored) if path.exists()]
    if not pins:return None
    if len(pins)==2 and pins[0]!=pins[1]:raise Refused('APPROVED_GATEWAY_MISMATCH')
    return pins[0]

def preapproved(receipt):
    expected=approved_receipt()
    if expected is None:return False
    if not binding_matches(expected,receipt):raise Refused('APPROVED_GATEWAY_MISMATCH')
    return True

def owned(path):
    st=path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise Refused('UNTRUSTED_OFFICIAL_FILE')
    for parent in path.parents:
        st=parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise Refused('UNTRUSTED_OFFICIAL_DIRECTORY')

def official_output():
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
    return output


def official_info():
    output=official_output()
    return choose_site(parse_sites(output),output)


def connected_object(output, host):
    """Only the Connected row in the one selected site's gateway list is eligible."""
    chunks=re.split(r'(?im)^[ \t]*Conn[ \t]+',output.replace('\r\n','\n'))
    blocks=[]
    for chunk in chunks[1:]:
        header,_,body=chunk.partition('\n')
        if header.strip().lower()==host+':':
            blocks.append(body)
    if len(blocks)!=1: raise Refused('OFFICIAL_GATEWAY_OBJECT_UNCONFIRMED')
    lists=re.split(r'(?im)^[ \t]*gateway list:[ \t]*\n',blocks[0])
    if len(lists)!=2: raise Refused('OFFICIAL_GATEWAY_OBJECT_UNCONFIRMED')
    names=[]
    for line in lists[1].splitlines():
        if not line.strip(): continue
        if not line.lstrip().startswith('('):
            if re.fullmatch(r'[ \t]*[A-Za-z][A-Za-z ]*:[^\n]*',line):break
            raise Refused('OFFICIAL_GATEWAY_OBJECT_UNCONFIRMED')
        match=re.fullmatch(r'[ \t]*\((Idle|Connected)\)[ \t]+([A-Za-z0-9][A-Za-z0-9_.-]{0,252})[ \t]*',line)
        if not match:raise Refused('OFFICIAL_GATEWAY_OBJECT_UNCONFIRMED')
        if match[1]=='Connected':names.append(match[2])
    if len(names)!=1:raise Refused('OFFICIAL_GATEWAY_OBJECT_UNCONFIRMED')
    return names[0]

def parse_sites(output):
    # Group by Conn before reading fields: no borrowing another site's status/IP.
    from sites import hostname
    rows={}
    chunks=re.split(r'(?im)^[ \t]*Conn[ \t]+',output.replace('\r\n','\n'))
    if len(chunks)==1:raise Refused('OFFICIAL_SITE_MISSING')
    if re.search(r'(?im)^[ \t]*(?:gw|status):',chunks[0]):raise Refused('OFFICIAL_STATE_UNKNOWN')
    for chunk in chunks[1:]:
        header,_,body=chunk.partition('\n')
        site=header.strip().removesuffix(':').lower()
        if not header.strip().endswith(':') or not hostname(site) or site in rows:
            raise Refused('OFFICIAL_SITE_FORMAT_UNSUPPORTED')
        def fields(key):return re.findall(r'(?im)^[ \t]*'+key+r':[ \t]*([^\n]*)$',body)
        states=[v.strip() for v in fields('status')]
        if len(states)!=1 or states[0] not in ('Idle','Connected','Connecting','Reconnecting'):
            raise Refused('OFFICIAL_STATE_UNKNOWN')
        ips=fields('gw')
        try:
            if len(ips)!=1:raise ValueError()
            ip=str(ipaddress.IPv4Address(ips[0].strip()))
        except ValueError:raise Refused('OFFICIAL_SITE_FORMAT_UNSUPPORTED') from None
        rows[site]=(site,ip,states[0])
    return rows

def selected_idle_site(output,rows):
    # "active site: true" selects a profile only. Certificate pins below are
    # still mandatory. Reject partial/malformed selections rather than guessing.
    choices=[]
    for block in re.split(r'(?im)^[ \t]*Conn[ \t]+',output.replace('\r\n','\n'))[1:]:
        header,_,body=block.partition('\n')
        name=header.strip().removesuffix(':').lower()
        flags=re.findall(r'(?im)^[ \t]*active site:[ \t]*([^\n]*)$',body)
        if len(flags)!=1 or flags[0].strip() not in ('true','false'):return None
        if flags[0].strip()=='true':choices.append(name)
    return rows.get(choices[0]) if len(choices)==1 else None


def choose_site(rows,output=''):
    path=DATA/'ssl-site.json'
    saved=None
    if path.exists():
        try:
            saved=json.loads(path.read_text())
            if not isinstance(saved['site'],str):raise ValueError()
            if 'dns_name' in saved:
                if saved['dns_name']!=saved['site'] or 'ip' in saved:raise ValueError()
            elif 'gateway_object' in saved:
                if (set(saved)!={'site','cn','ca_sha256','gateway_object','leaf_sha256'} or
                        not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}',saved['gateway_object']) or
                        not re.fullmatch(r'[a-f0-9]{64}',saved['leaf_sha256'])):raise ValueError()
            elif 'leaf_sha256' in saved:
                if (set(saved)!={'site','cn','ca_sha256','leaf_sha256'} or
                        not re.fullmatch(r'[a-f0-9]{64}',saved['leaf_sha256'])):raise ValueError()
            else:ipaddress.IPv4Address(saved['ip'])
        except (OSError,KeyError,ValueError,TypeError):raise Refused('SAVED_SITE_OR_PIN_CHANGED') from None
    active=[r for r in rows.values() if r[2]!='Idle']
    if len(active)>1:raise Refused('OFFICIAL_STATE_UNKNOWN')
    primary=approved_receipt()
    pin=approved_site_pin()
    preferred=None
    preference=DATA/'preferred-site.json'
    if not saved and preference.exists():
        try:
            value=json.loads(preference.read_text())
            allowed={p['site'] for p in (primary,pin) if p}
            if not isinstance(value,dict) or set(value)!={'site'} or value['site'] not in allowed:
                raise ValueError()
            preferred=rows.get(value['site'])
            if preferred is None:raise Refused('SELECTED_SITE_MISSING')
        except (OSError,TypeError,KeyError,ValueError):raise Refused('INVALID_SITE_SELECTION') from None
    if saved:
        row=rows.get(saved['site'])
        if not row:raise Refused('SAVED_SITE_OR_PIN_CHANGED')
        if active and active[0]!=row:raise Refused('OFFICIAL_OTHER_SITE_ACTIVE')
    elif preferred:
        row=preferred
        if active and active[0]!=row:raise Refused('OFFICIAL_OTHER_SITE_ACTIVE')
    elif len(rows)==1:row=next(iter(rows.values()))
    elif active and active[0][2]=='Connected':row=active[0]
    elif not active and pin and primary:
        row=selected_idle_site(output,rows)
        if not row or row[0] not in (pin['site'],primary['site']):raise Refused('OFFICIAL_SITE_AMBIGUOUS')
    else:raise Refused('OFFICIAL_SITE_AMBIGUOUS')
    expected=os.environ.get('CVR_ATTEMPT_GATEWAY')
    if expected is not None and expected!=row[0]+'@'+row[1]:raise Refused('OFFICIAL_SELECTION_CHANGED')
    if primary and row[0]!=primary['site'] and not saved and row[2]!='Connected' and not (pin and row[0]==pin['site']):
        raise Refused('OFFICIAL_CONNECT_ASSIGNED_SITE')
    return row

GATEWAY_DNS_BUDGET = 40.0
GATEWAY_DNS_RETRY_DELAY = 1.0


def gateway_ipv4(host, deadline):
    # getaddrinfo uses macOS scoped DNS and has no caller-supplied timeout.
    # A stalled lookup can outlive the wait, but never the session process.
    result = Future()
    def lookup():
        try:
            rows = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
            result.set_result({row[4][0] for row in rows})
        except Exception as error:
            result.set_exception(error)

    threading.Thread(target=lookup, daemon=True).start()
    try:
        return result.result(timeout=max(0, deadline - time.monotonic()))
    except FutureTimeout as error:
        raise Refused('GATEWAY_DNS_TIMEOUT') from error


def site(require_idle=True, report_dns=None):
    host,ip,state=official_info()
    if require_idle and state!='Idle': raise Refused('OFFICIAL_VPN_NOT_IDLE')
    deadline = time.monotonic() + GATEWAY_DNS_BUDGET
    if report_dns:
        report_dns('gateway_dns_lookup')
    for attempt in (1, 2):
        try:
            addresses = gateway_ipv4(host, deadline)
            break
        except socket.gaierror as error:
            # Darwin can also return EAI_NONAME after a 30 s DNS timeout.
            retryable = error.errno in (socket.EAI_AGAIN, socket.EAI_NONAME,
                                        getattr(socket, 'EAI_NODATA', socket.EAI_NONAME))
            if not retryable or attempt == 2:
                raise Refused('GATEWAY_DNS_UNRESOLVED') from error
            if time.monotonic() + GATEWAY_DNS_RETRY_DELAY >= deadline:
                raise Refused('GATEWAY_DNS_TIMEOUT') from error
            if report_dns:
                report_dns('gateway_dns_retry', errno=error.errno)
            time.sleep(GATEWAY_DNS_RETRY_DELAY)
    if ip not in addresses:
        raise Refused('SITE_ADDRESS_MISMATCH')
    if attempt == 2 and official_info() != (host, ip, state):
        raise Refused('OFFICIAL_SELECTION_CHANGED')
    if report_dns:
        report_dns('gateway_dns_verified')
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
    # A partly parsed entry (including a malformed duplicate) is not evidence.
    if len(entries)!=section.count(':--Fingerprint--') or len(entries)!=len(re.findall(r':\s*\("',section)):
        raise Refused('OFFICIAL_PIN_MISMATCH')
    if [pin for name,pin in entries if name==cn]!=[words]: raise Refused('OFFICIAL_PIN_MISMATCH')


def private_reference(sans):
    if len(sans)!=1 or sans[0][0]!='IP Address':raise Refused('SITE_SAN_MISMATCH')
    reference=ipaddress.ip_address(sans[0][1])
    if reference.version!=4 or not any(reference in ipaddress.ip_network(cidr)
            for cidr in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')):
        raise Refused('SITE_SAN_MISMATCH')
    return str(reference)


def private_gateway_binding(host, ip, cn, sans, leaf_der):
    # Only a separately assigned site can use this identity method. Never
    # replace a primary site pin or a previously enrolled DNS/IP identity.
    primary=approved_receipt()
    if not primary or primary['site']==host:raise Refused('SITE_SAN_MISMATCH')
    saved_path=DATA/'ssl-site.json'
    saved=json.loads(saved_path.read_text()) if saved_path.exists() else None
    if saved is not None and 'gateway_object' not in saved:raise Refused('SAVED_SITE_OR_PIN_CHANGED')
    reference=private_reference(sans)
    output=official_output()
    site_name,dial,state=choose_site(parse_sites(output))
    if (site_name,dial)!=(host,ip):raise Refused('OFFICIAL_SELECTION_CHANGED')
    if state=='Connected':
        name=connected_object(output,host)
    elif state=='Idle' and saved is not None:
        name=saved['gateway_object']
    else:raise Refused('OFFICIAL_CONNECT_ASSIGNED_SITE')
    if cn not in (name, name+' VPN Certificate'):
        raise Refused('OFFICIAL_GATEWAY_OBJECT_UNCONFIRMED')
    identity=dict(gateway_object=name,leaf_sha256=hashlib.sha256(leaf_der).hexdigest())
    if saved is not None and any(saved[k]!=v for k,v in identity.items()):
        raise Refused('SAVED_SITE_OR_PIN_CHANGED')
    return reference,identity


def anchor(approve, require_idle=True, resilient=False, confirm_other_ca=None, report_dns=None):
    host,ip=site(require_idle=require_idle, report_dns=report_dns)
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
        if len(names)!=1: raise Refused('GATEWAY_CN_UNSUPPORTED')
        sans=decoded.get('subjectAltName', ())
        # Select the reference from the signed site record. OpenSSL verifies
        # it again during each actual handshake, including wildcard semantics.
        dns_match=any(kind=='DNS' and value.lower() in (host,'*.'+host.partition('.')[2])
                      for kind,value in sans)
        tls_name=host if dns_match else ip
        leaf_der=ssl.PEM_cert_to_DER_cert(chain[0].decode())
        der=ssl.PEM_cert_to_DER_cert(chain[-1].decode())
        digest=hashlib.sha256(der).hexdigest()
        primary=approved_receipt()
        pin=approved_site_pin()
        prebound=bool(pin and primary and pin['site']==host and primary['site']!=host)
        object_identity=None
        if prebound:
            if pin['ca_sha256']!=digest or pin['leaf_sha256']!=hashlib.sha256(leaf_der).hexdigest():
                raise Refused('APPROVED_GATEWAY_MISMATCH')
        if not dns_match and ('IP Address',ip) not in sans:
            if prebound:tls_name=private_reference(sans)
            else:tls_name,object_identity=private_gateway_binding(host,ip,names[0],sans,leaf_der)
        # A release-provisioned exact leaf and CA already establish identity.
        # Unprovisioned sites continue to require the native accepted fingerprint.
        if not prebound:accepted(names[0],fingerprint(der))
        ca=Path(d)/'ca';ca.write_bytes(chain[-1])
        ctx=pinned_context(ca,digest)
        if dns_match and ctx.hostname_checks_common_name:
            raise Refused('DNS_SAN_VERIFIER_UNAVAILABLE')
        ctx.gateway_tls_name=tls_name
        if object_identity is not None or prebound:
            pin_gateway_leaf(ctx,leaf_der)
            ctx.gateway_http_host=host
        connector=socket.create_connection
        if resilient:
            from connection_resilience import connect
            connector=connect
        with connector((ip,443),timeout=10) as raw,ctx.wrap_socket(raw,server_hostname=tls_name) as tls:
            if tls.getpeercert(binary_form=True)!=leaf_der: raise Refused('GATEWAY_CHANGED')
    receipt={'site':host,'cn':names[0],'ca_sha256':digest}
    if prebound:receipt['leaf_sha256']=pin['leaf_sha256']
    else:receipt.update(object_identity or ({'dns_name':host} if dns_match else {'ip':ip}))
    display=dict(receipt,ip=ip)
    path=DATA/'ssl-site.json'
    if primary and host!=primary['site']:
        # This is a separate enrollment, never a fallback for a changed pin
        # on the preconfigured site. Bind it to this exact bootstrap as well.
        enrollment=DATA/'official-alternate-binding.json'
        proof={'primary':primary,'alternate':receipt}
        if path.exists() and not binding_matches(json.loads(path.read_text()),receipt):
            raise Refused('SAVED_SITE_OR_PIN_CHANGED')
        if enrollment.exists():
            previous=json.loads(enrollment.read_text())
            if (not isinstance(previous,dict) or previous.get('primary')!=primary or
                    not binding_matches(previous.get('alternate'),receipt)):
                raise Refused('SAVED_SITE_OR_PIN_CHANGED')
        elif not prebound:
            if official_info()!=(host,ip,'Connected'):raise Refused('OFFICIAL_CONNECT_ASSIGNED_SITE')
            if primary['ca_sha256']!=digest:
                if confirm_other_ca is None or not confirm_other_ca(host,digest):
                    raise Refused('ALTERNATE_CA_NOT_CONFIRMED')
            else:approve(display)
            # Consent may take time; never bind a site which changed meanwhile.
            if official_info()!=(host,ip,'Connected'):raise Refused('OFFICIAL_SELECTION_CHANGED')
            if object_identity:
                _,current=private_gateway_binding(host,ip,names[0],sans,leaf_der)
                if current!=object_identity:raise Refused('OFFICIAL_SELECTION_CHANGED')
            with enrollment.open('x') as f:json.dump(proof,f)
        if prebound and official_info()[:2]!=(host,ip):raise Refused('OFFICIAL_SELECTION_CHANGED')
        already_verified=True
    else:already_verified=preapproved(receipt)
    if path.exists():
        if not binding_matches(json.loads(path.read_text()),receipt):raise Refused('SAVED_SITE_OR_PIN_CHANGED')
    else:
        if not already_verified:approve(display)
        with path.open('x') as f: json.dump(receipt,f)
    return ip,ctx
