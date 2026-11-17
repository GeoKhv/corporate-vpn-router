"""Unprivileged JSON pipe to the pinned native XPC client. No elevation."""
import asyncio
import json

class RouteHelper:
    def __init__(self, resources):
        self.executable = resources/'RouteHelper/RouteClient'
        self.process = None
        self.lock = asyncio.Lock()

    async def open(self):
        self.process = await asyncio.create_subprocess_exec(str(self.executable),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL)
        return await self.call('status')

    async def call(self, operation, **fields):
        async with self.lock:
            if self.process is None or self.process.returncode is not None:
                raise RuntimeError('HELPER_UNAVAILABLE')
            data = json.dumps(dict(op=operation, **fields)).encode()+b'\n'
            if len(data) > 65536:
                raise ValueError('Helper request too large')
            self.process.stdin.write(data)
            await self.process.stdin.drain()
            line = await asyncio.wait_for(self.process.stdout.readline(), 35)
            if not line:
                raise RuntimeError('HELPER_UNAVAILABLE')
            result = json.loads(line)
            if not result.get('ok'):
                raise RuntimeError(result.get('error', 'HELPER_REQUEST_FAILED'))
            return result

    async def close(self):
        if self.process:
            self.process.stdin.close()
            try:
                await asyncio.wait_for(self.process.wait(), 5)
            except asyncio.TimeoutError:
                self.process.kill()
                await self.process.wait()
