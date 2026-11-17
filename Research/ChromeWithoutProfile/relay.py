"""Private HTTP router: production implementation and unchanged verified SOCKS peer.
Only this laboratory's work-down file injects failure. Never touches the tunnel.
"""
import argparse,asyncio,sys
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--data',type=Path,required=True);p.add_argument('--port',type=int,required=True);args=p.parse_args()
root=Path(__file__).resolve().parents[2];sys.path.insert(0,str(root/'Backend'))
import http_router as h
h.DATA=args.data.resolve();h.PORT=args.port
h.SOCKS_CONTROL=str(Path.home()/'Library/Application Support/Corporate VPN Router/socks-worker.sock')
original=h.via_socks
async def connect(host,port):
 if (h.DATA/'work-down').exists():raise OSError('isolated work fault')
 return await original(host,port)
h.via_socks=connect
asyncio.run(h.main())
