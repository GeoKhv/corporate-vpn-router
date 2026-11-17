"""Disposable Chrome CDP pipe, never attaches to a user's browser."""
import json,os,select,signal,time
class Browser:
    def __init__(self,executable,directory,extra=()):
        a,b=os.pipe();c,d=os.pipe()
        args=[str(executable),'--headless','--remote-debugging-pipe','--disable-extensions','--no-first-run','--disable-background-networking','--user-data-dir='+str(directory),*extra,'about:blank']
        try:
            self.pid=os.posix_spawn(str(executable),args,os.environ,file_actions=[(os.POSIX_SPAWN_DUP2,a,3),(os.POSIX_SPAWN_DUP2,d,4),(os.POSIX_SPAWN_OPEN,2,os.devnull,os.O_WRONLY,0)])
        finally:os.close(a);os.close(d)
        self.r=c;self.w=b;self.buf=b'';self.i=0;self.events=[]
    def msg(self):
        while b'\0' not in self.buf:
            if not select.select([self.r],[],[],25)[0]:raise TimeoutError('CDP response')
            chunk=os.read(self.r,65536)
            if not chunk:raise RuntimeError('Chrome exited')
            self.buf+=chunk
        msg,self.buf=self.buf.split(b'\0',1);return json.loads(msg)
    def call(self,method,params=None,session=None):
        self.i+=1;msg=dict(id=self.i,method=method,params=params or {})
        if session:msg['sessionId']=session
        os.write(self.w,json.dumps(msg).encode()+b'\0')
        while True:
            r=self.msg()
            if r.get('id')==self.i:
                if 'error' in r:raise RuntimeError(r['error'])
                return r['result']
            self.events.append(r)
    def page(self,url):
        t=self.call('Target.createTarget',{'url':'about:blank'})['targetId']
        try:
            s=self.call('Target.attachToTarget',{'targetId':t,'flatten':True})['sessionId']
            nav=self.call('Page.navigate',{'url':url},s)
            if nav.get('errorText'):return nav['errorText'],''
            for _ in range(100):
                v=self.call('Runtime.evaluate',{'expression':'document.readyState+"|"+(document.body?.innerText||"")','returnByValue':True},s)['result'].get('value','')
                if v.startswith('complete|') and len(v)>9:return '',v
                time.sleep(.05)
            return '',v
        finally:self.call('Target.closeTarget',{'targetId':t})
    def close(self):
        try:self.call('Browser.close')
        except (RuntimeError,OSError):pass
        for _ in range(100):
            if os.waitpid(self.pid,os.WNOHANG)[0]:break
            time.sleep(.05)
        else:os.kill(self.pid,signal.SIGTERM);os.waitpid(self.pid,0)
        os.close(self.r);os.close(self.w)
