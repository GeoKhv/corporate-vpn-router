"""First-use approval is skipped only after strict TLS + official pin + manifest match."""
import hashlib,json,socket,ssl,subprocess,sys,tempfile
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(sys.argv[1]).resolve()))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import trust
if '--resilient' in sys.argv:
 original_anchor=trust.anchor
 trust.anchor=lambda *args,**kwargs:original_anchor(*args,**kwargs,resilient=True)
from beta_tls import Fixture,openssl
with tempfile.TemporaryDirectory(prefix='cvr-gateway-approval-',dir='/private/tmp') as tmp:
 base=Path(tmp);data=base/'data';data.mkdir();(base/'registry').mkdir()
 (base/'ca.cnf').write_text('[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n[dn]\nCN=Fixture Root\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n')
 openssl(base,'req','-new','-x509','-newkey','rsa:2048','-nodes','-days','1','-config','ca.cnf','-keyout','ca.key','-out','ca.pem')
 openssl(base,'req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=Fixture Gateway','-keyout','leaf.key','-out','leaf.csr')
 (base/'leaf.cnf').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n')
 openssl(base,'x509','-req','-in','leaf.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-days','1','-extfile','leaf.cnf','-out','valid.pem')
 certs=(base/'valid.pem').read_bytes()+(base/'ca.pem').read_bytes()
 expected={'site':'gateway.invalid','ip':'127.0.0.1','cn':'Fixture Gateway','ca_sha256':hashlib.sha256(ssl.PEM_cert_to_DER_cert((base/'ca.pem').read_text())).hexdigest()}
 manifest=base/'ApprovedGateway.json'
 def approve_config(receipt=expected):manifest.write_text(json.dumps(dict(schema=1,receipt=receipt,automaticFirstUse=True,provenance='OWNER_APPROVED_EXISTING_OFFICIAL_CLIENT_PIN_AND_STRICT_LIVE_TLS')))
 registry=base/'registry/HKLM_registry.data'
 registry.write_text(': (accepted_cn\n: ("Fixture Gateway" :--Fingerprint-- ("FIXTURE WORDS"))\n)')
 fixture=Fixture(base,'valid.pem');real_socket=socket.create_connection;approvals=[]
 try:
  with patch.object(trust,'DATA',data),patch.object(trust,'CP',base),patch.object(trust,'APPROVED_GATEWAY',manifest),patch.object(trust,'owned'),patch.object(trust,'site',return_value=('gateway.invalid','127.0.0.1')),patch.object(trust,'fingerprint',return_value='FIXTURE WORDS'),patch.object(trust.subprocess,'run',return_value=subprocess.CompletedProcess([],0,certs)),patch('socket.create_connection',lambda addr,*a,**kw:real_socket(('127.0.0.1',fixture.port),*a,**kw)):
   approve_config();_,ctx=trust.anchor(approvals.append)
   assert approvals==[] and json.loads((data/'ssl-site.json').read_text())==expected
   assert ctx.check_hostname and ctx.verify_mode==ssl.CERT_REQUIRED
   trust.anchor(approvals.append);assert approvals==[]
   (data/'ssl-site.json').unlink();manifest.unlink();trust.anchor(approvals.append)
   assert approvals==[expected], 'generic builds retain explicit confirmation'
   (data/'ssl-site.json').unlink();approve_config(dict(expected,ca_sha256='0'*64))
   try:trust.anchor(approvals.append)
   except trust.Refused as e:assert str(e)=='APPROVED_GATEWAY_MISMATCH'
   else:raise AssertionError('unknown/changed CA auto-approved')
   assert not (data/'ssl-site.json').exists() and len(approvals)==1
   approve_config();registry.write_text(': (accepted_cn\n: ("Fixture Gateway" :--Fingerprint-- ("OTHER WORDS"))\n)')
   before=fixture.accepts
   try:trust.anchor(approvals.append)
   except trust.Refused as e:assert str(e)=='OFFICIAL_PIN_MISMATCH'
   else:raise AssertionError('manifest bypassed official pin')
   assert fixture.accepts==before
   registry.write_text(': (accepted_cn\n: ("Fixture Gateway" :--Fingerprint-- ("FIXTURE WORDS"))\n)')
   (data/'ssl-site.json').write_text(json.dumps(dict(expected,ip='192.0.2.1')))
   try:trust.anchor(approvals.append)
   except trust.Refused as e:assert str(e)=='SAVED_SITE_OR_PIN_CHANGED'
   else:raise AssertionError('saved binding replaced')
   manifest.write_text('{}')
   try:trust.anchor(approvals.append)
   except trust.Refused as e:assert str(e)=='APPROVED_GATEWAY_INVALID'
   else:raise AssertionError('malformed manifest accepted')
 finally:fixture.close()
 assert not fixture.application_data, 'trust checks sent application data'
print('PASS exact approved first/repeat trust without prompt; generic approval; unknown/changed CA; official pin; saved binding; malformed manifest; no application data')
