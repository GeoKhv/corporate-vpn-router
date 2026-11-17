"""Root local DNS frontend: exact host routes before each fake DNS response.
No external DNS socket is used. Unknown names never reach another resolver.
Used only by the bounded laboratory supervisor.
"""
import asyncio
import ipaddress
import json
import struct
import subprocess
import time

def decode_name(buf,pos):
    labels=[];end=None;seen=set()
    while True:
        if pos in seen:raise ValueError('DNS compression cycle')
        seen.add(pos);n=buf[pos];pos+=1
        if n&0xc0==0xc0:
            offset=((n&63)<<8)|buf[pos];pos+=1
            if end is None:end=pos
            pos=offset;continue
        if n>63:raise ValueError('label')
        if not n:return '.'.join(labels).lower(), end or pos
        labels.append(buf[pos:pos+n].decode('ascii'));pos+=n

def allowed(name,policy):
    return name=='work.cvr-probe.invalid' or (name not in policy['beforeLogin'] and any(
        name==r['domain'] or (r['scope']=='tree' and name.endswith('.'+r['domain'])) for r in policy['sites']))

async def serve(policy,stage,stop):
    log=(stage/'dns-front.jsonl').open('a',buffering=1)
    routes=set();lock=asyncio.Lock()
    cfg=json.loads((stage/'trial-input.json').read_text())
    stable=cfg.get('mode')=='stable-map'
    pools=[ipaddress.ip_network('198.18.75.0/24' if stable else '198.18.74.0/24'),
           ipaddress.ip_network('fdc7:7652:9a10:75::/120' if stable else 'fdc7:7652:9a10:74::/120')]
    async def answer(packet):
        ident,flags,qd,_,_,_=struct.unpack('!6H',packet[:12])
        if qd!=1 or flags&0xf800:raise ValueError('question')
        name,pos=decode_name(packet,12);kind,cls=struct.unpack('!HH',packet[pos:pos+4]);end=pos+4
        log.write(json.dumps(dict(time=time.time(),name=name,type=kind,event='query'))+'\n')
        if not allowed(name,policy) or cls!=1:
            return struct.pack('!6H',ident,0x8183,1,0,0,0)+packet[12:end]
        # TCP loopback to the local synthetic DNS service. Never public DNS.
        r,w=await asyncio.wait_for(asyncio.open_connection('127.0.0.1',cfg.get('dns_backend_port',53542)),3)
        try:
            w.write(struct.pack('!H',len(packet))+packet);await w.drain()
            size=struct.unpack('!H',await asyncio.wait_for(r.readexactly(2),3))[0]
            response=await asyncio.wait_for(r.readexactly(size),3)
        finally:w.close()
        rid,_,qd,an,_,_=struct.unpack('!6H',response[:12]);assert rid==ident and qd==1
        _,pos=decode_name(response,12);pos+=4
        addresses=[]
        for _ in range(an):
            _,pos=decode_name(response,pos)
            typ,rclass,ttl,size=struct.unpack('!HHIH',response[pos:pos+10]);pos+=10
            if typ in (1,28):
                ip=ipaddress.ip_address(response[pos:pos+size])
                assert any(ip.version==p.version and ip in p for p in pools),'non-synthetic DNS answer'
                addresses.append(ip)
            elif typ==5:raise ValueError('unexpected CNAME')
            pos+=size
        async with lock:
            for ip in addresses:
                if str(ip) in routes:continue
                family='-inet' if ip.version==4 else '-inet6'
                proc=await asyncio.create_subprocess_exec('/sbin/route','-n','add',family,'-host',str(ip),'-interface','utun73',
                     stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
                out,err=await proc.communicate()
                check=await asyncio.create_subprocess_exec('/sbin/route','-n','get',family,str(ip),stdout=asyncio.subprocess.PIPE)
                actual,_=await check.communicate()
                if b'interface: utun73' not in actual:raise OSError('host route missing')
                routes.add(str(ip));(stage/'host-routes.json').write_text(json.dumps(sorted(routes)))
                log.write(json.dumps(dict(time=time.time(),event='host_route',name=name,address=str(ip),stderr=err.decode()))+'\n')
        return response
    class UDP(asyncio.DatagramProtocol):
        def connection_made(self,t):self.t=t
        def datagram_received(self,p,addr):asyncio.create_task(self.reply(p,addr))
        async def reply(self,p,addr):
            try:self.t.sendto(await answer(p),addr)
            except Exception as e:
                log.write(json.dumps(dict(event='error',error=str(e)))+'\n')
                response=negative(p)
                if response:self.t.sendto(response,addr)
    def negative(packet):
        # A valid local question gets a conclusive refusal even if the bridge
        # or route operation fails. Do not invite resolver fallback by silence.
        try:
            ident,flags,qd,_,_,_=struct.unpack('!6H',packet[:12])
            if qd!=1 or flags&0xf800:return None
            _,pos=decode_name(packet,12)
            if pos+4>len(packet):return None
            return struct.pack('!6H',ident,0x8483|(flags&0x100),1,0,0,0)+packet[12:pos+4]
        except (ValueError,IndexError,struct.error,UnicodeError):return None
    async def tcp(r,w):
        try:
            while True:
                n=struct.unpack('!H',await asyncio.wait_for(r.readexactly(2),5))[0]
                packet=await asyncio.wait_for(r.readexactly(n),5)
                try:reply=await answer(packet)
                except Exception as exc:
                    log.write(json.dumps(dict(event='error',error=str(exc)))+'\n')
                    reply=negative(packet)
                    if reply is None:break
                w.write(struct.pack('!H',len(reply))+reply);await w.drain()
        except (Exception,asyncio.CancelledError):pass
        finally:w.close()
    # A browser may retain an old DNS answer across adapter restarts. Rebuild
    # the exact host routes for durable names BEFORE publishing DNS readiness.
    warmup=cfg.get('retained_names',[])
    if not isinstance(warmup,list) or len(warmup)>253:raise ValueError('invalid retained names')
    if warmup and not stable:raise ValueError('retained names require stable mapping')
    for name in warmup:
        if not isinstance(name,str) or not allowed(name,policy):raise ValueError('retained name outside policy')
        labels=name.encode('ascii').split(b'.')
        if not labels or any(not x or len(x)>63 for x in labels):raise ValueError('retained name format')
        for kind in (1,28):
            question=struct.pack('!6H',1,0x100,1,0,0,0)+b''.join(bytes([len(x)])+x for x in labels)+b'\0'+struct.pack('!HH',kind,1)
            response=await answer(question)
            if response[3]&15:raise ValueError('retained mapping unavailable')
    log.write(json.dumps(dict(time=time.time(),event='retained_routes_ready',names=len(warmup),routes=len(routes)))+'\n')
    udp,_=await asyncio.get_running_loop().create_datagram_endpoint(UDP,local_addr=('127.0.0.1',cfg['dns_port']))
    server=await asyncio.start_server(tcp,'127.0.0.1',cfg['dns_port'])
    (stage/'dns-ready').touch()
    try:
        while not stop():await asyncio.sleep(.1)
    finally:udp.close();server.close();log.close()

if __name__=='__main__':
    from pathlib import Path
    import signal
    import sys
    stage=Path(sys.argv[1]);cfg=json.loads((stage/'trial-input.json').read_text());done=False
    def end(sig,frame):
        global done
        done=True
    signal.signal(signal.SIGTERM,end);signal.signal(signal.SIGINT,end)
    asyncio.run(serve(cfg['policy'],stage,lambda:done))
