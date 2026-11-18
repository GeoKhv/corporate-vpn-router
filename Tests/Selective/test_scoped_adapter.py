"""Ordinary TCP stream through real sing-box and policy bridge. Loopback fixture only."""
import asyncio,contextlib,ipaddress,json,os,socket,struct,sys,tempfile
from pathlib import Path
from types import SimpleNamespace
engine=Path(sys.argv[1]).resolve()
sys.path[:0]=[str(engine),str(engine/'Selective')]
from services import serve
from http_router import is_work,pump
from domain_map import DomainMap
from analyze import analyze

async def main():
    with tempfile.TemporaryDirectory() as tmp:
        d=Path(tmp)
        def available():
            with socket.socket() as s:
                s.bind(('127.0.0.1',0));return s.getsockname()[1]
        async def echo(reader,writer):
            try:
                data=await reader.read(32);writer.write(data);await writer.drain()
            finally:writer.close()
        remote=await asyncio.start_server(echo,'127.0.0.1',0)
        full='node.lab.invalid'; policy={'version':2,'sites':[{'domain':'lab.invalid','scope':'tree','tcp':[443]},
            {'domain':full,'scope':'exact','tcp':[22,6443],'alias':'node'}],'ports':[443],'beforeLogin':[]}
        (d/'work-sites.json').write_text(json.dumps(policy))
        suggestion=await analyze('other.lab.invalid:22',d,d)
        assert suggestion['stage'] in ('port','tcp') # installed helper may be absent in a test bundle
        suggestion=await analyze('new.service.invalid:22',d,d)
        assert suggestion['stage']=='no_rule' and suggestion['host']=='new.service.invalid' and suggestion['port']==22
        async def via(name,port,resolve_only=False):
            if name != full:raise OSError('fixture unknown name')
            if not resolve_only and port not in (22,6443):raise AssertionError(port)
            return await asyncio.open_connection('127.0.0.1',remote.sockets[0].getsockname()[1])
        fixture=SimpleNamespace(is_work=is_work,pump=pump,via_socks=via)
        registry=DomainMap(d/'map');ip=registry.address(full,4);ip6=registry.address(full,6)
        assert ip.endswith('.2') and ip6.endswith('::2')
        stop=asyncio.Event()
        cfg=dict(mode='stable-map',map_path=str(d/'map'),policy=policy,password='synthetic',host=full,
                 verify_names=True,dns_backend_port=available(),socks_port=available())
        serve_task=asyncio.create_task(serve(cfg,d,fixture,stop_event=stop))
        for _ in range(50):
            if (d/'services.pid').exists():break
            await asyncio.sleep(.03)
        async def dns(name,kind):
            query=struct.pack('!6H',4,256,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+struct.pack('!HH',kind,1)
            reader,writer=await asyncio.open_connection('127.0.0.1',cfg['dns_backend_port'])
            writer.write(struct.pack('!H',len(query))+query)
            size,=struct.unpack('!H',await reader.readexactly(2));answer=await reader.readexactly(size);writer.close()
            return (None if answer[3]&15 else str(ipaddress.ip_address(answer[-(4 if kind==1 else 16):])))
        assert await dns('node',1)==ip and await dns(full,28)==ip6
        assert await dns('missing.lab.invalid',1) is None
        inbounds=[];ports=[]
        for addr,port in ((ip,22),(ip6,6443),(ip,80)):
            entry=available();ports.append(entry)
            inbounds.append(dict(type='direct',tag='fixture-'+str(port),listen='127.0.0.1',listen_port=entry,override_address=addr,override_port=port))
        setfile=d/'rules.json'
        setfile.write_text(json.dumps({'version':3,'rules':[]}))
        config={'log':{'level':'warn'},'inbounds':inbounds,
         'outbounds':[dict(type='socks',tag='verified-work',server='127.0.0.1',server_port=cfg['socks_port'],version='5',username='trial',password=cfg['password'])],
         'route':{'rule_set':[dict(type='local',tag='approved-tcp',format='source',path=str(setfile))],
                  'rules':[dict(network='tcp',rule_set=['approved-tcp'],action='route',outbound='verified-work'),dict(action='reject',no_drop=True)]}}
        path=d/'config.json';path.write_text(json.dumps(config))
        proc=await asyncio.create_subprocess_exec(str(engine.parent/'RouteHelper/sing-box'),'run','-c',str(path),stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.PIPE)
        async def ordinary(port):
            try:
                r,w=await asyncio.open_connection('127.0.0.1',port)
                try:w.write(b'ordinary client');await w.drain();return await asyncio.wait_for(r.read(32),1)==b'ordinary client'
                finally:w.close()
            except (OSError,asyncio.TimeoutError):return False
        try:
            await asyncio.sleep(.5)
            if proc.returncode is not None:raise AssertionError((await proc.stderr.read()).decode())
            assert not await ordinary(ports[0])
            nxt=d/'rules.next';nxt.write_text(json.dumps({'version':3,'rules':[{'ip_cidr':[ip+'/32',ip6+'/128'],'port':[22,6443]}]}));nxt.replace(setfile)
            for _ in range(60):
                if await ordinary(ports[0]):break
                await asyncio.sleep(.1)
            else:raise AssertionError('TCP rule reload did not become effective')
            assert await ordinary(ports[1]);assert not await ordinary(ports[2])
            stop.set();await serve_task
            assert not await ordinary(ports[0])
            assert DomainMap(d/'map').name_for_ip(ip6)==full
        finally:
            if proc.returncode is None:proc.terminate()
            await proc.wait()
            stop.set();await serve_task;remote.close();await remote.wait_closed()
    print('PASS normal TCP loopback clients, live rule reload, IPv4/IPv6 22/6443 echo, denied port, alias mapping, transport loss, retained map and exact suggestion')

asyncio.run(asyncio.wait_for(main(),25))
