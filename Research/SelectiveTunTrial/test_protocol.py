"""Real sing-box SOCKS wire test using only loopback and reserved .invalid."""
import asyncio
import json
from pathlib import Path
import socket
import struct
import sys
import tempfile
from services import dns_answer

def question(name,kind):
    return struct.pack('!6H',23,0x100,1,0,0,0)+b''.join(bytes([len(p)])+p.encode() for p in name.split('.'))+b'\0'+struct.pack('!HH',kind,1)

async def test(binary):
    cfg=dict(host='work.cvr.invalid',ipv4='198.18.73.2',ipv6='fdc7:7652:9a10::2')
    for kind,n in [(1,4),(28,16),(65,0),(64,0)]:
        reply,event=dns_answer(question(cfg['host'],kind),cfg)
        assert struct.unpack('!6H',reply[:12])[3]==bool(n)
        if n:assert struct.unpack('!H',reply[-n-2:-n])[0]==n
    assert dns_answer(question('child.'+cfg['host'],1),cfg)[0][3]&15==3
    assert dns_answer(question('outside.invalid',1),cfg)[0][3]&15==3
    witnessed=asyncio.Future()
    async def socks(r,w):
        try:
            ver,n=await r.readexactly(2); methods=await r.readexactly(n)
            assert ver==5 and 0 in methods;w.write(b'\x05\x00')
            ver,cmd,res,atyp=await r.readexactly(4)
            assert (ver,cmd,res,atyp)==(5,1,0,3)
            n=(await r.readexactly(1))[0];name=(await r.readexactly(n)).decode()
            port=struct.unpack('!H',await r.readexactly(2))[0]
            assert name==cfg['host'] and port==443
            witnessed.set_result(dict(atyp=atyp,host=name,port=port))
            w.write(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
            data=await r.readexactly(12);w.write(data);await w.drain()
        except Exception as e:
            if not witnessed.done():witnessed.set_exception(e)
        finally:w.close()
    server=await asyncio.start_server(socks,'127.0.0.1',0)
    proxy_port=server.sockets[0].getsockname()[1]
    with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
    config={'inbounds':[{'type':'direct','tag':'one-name','listen':'127.0.0.1','listen_port':port,
        'override_address':cfg['ipv4'],'override_port':443}],
        'outbounds':[{'type':'socks','tag':'work','server':'127.0.0.1','server_port':proxy_port,'version':'5'}],
        'route':{'rules':[{'inbound':['one-name'],'ip_cidr':[cfg['ipv4']+'/32'],'network':'tcp','port':[443],
        'action':'route','override_address':cfg['host'],'outbound':'work'},{'action':'reject'}]}}
    with tempfile.TemporaryDirectory(prefix='cvr-wire-') as tmp:
        p=Path(tmp)/'config.json';p.write_text(json.dumps(config))
        proc=await asyncio.create_subprocess_exec(binary,'run','-c',str(p),stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.PIPE)
        try:
            for _ in range(40):
                try:r,w=await asyncio.open_connection('127.0.0.1',port);break
                except OSError:await asyncio.sleep(.1)
            else:raise AssertionError('sing-box did not start')
            w.write(b'opaque-bytes');await w.drain()
            assert await asyncio.wait_for(r.readexactly(12),4)==b'opaque-bytes'
            result=await witnessed
            w.close()
            print(json.dumps(dict(dns_exact_A_AAAA=True,https_svcb_nodata=True,unknown_name_rejected=True,socks_wire=result,tls_payload_opaque=True)))
        finally:
            proc.terminate();await proc.wait()
    server.close();await server.wait_closed()

asyncio.run(test(sys.argv[1]))
