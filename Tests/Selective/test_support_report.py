"""Verify the shareable artifact, including redaction, missing sources and partial history."""
import json
import os
from pathlib import Path
import plistlib
import stat
import sys
import tempfile
from unittest.mock import patch

root=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(root/'Backend'),str(root/'scripts')]
import support_report as report
import trust
from report_terms import write_terms


def write(path, value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value)+'\n')


with tempfile.TemporaryDirectory(dir='/private/tmp') as folder:
    home=Path(folder)
    data=home/'data'
    logs=home/'logs'
    res=home/'app/Contents/Resources'
    res.mkdir(parents=True)
    write_terms(root,res/'ReportTerms.json')
    (res.parent/'Info.plist').write_bytes(plistlib.dumps({'CFBundleVersion':'3013','CFBundleShortVersionString':'0.3.13'}))
    secret='USER_PRIVATE_BEARER_568942'
    def local_command(argv, **kw):
        if argv[0]=='/usr/bin/log':
            return 'ok',json.dumps({'processImagePath':'/Applications/TracSrvWrapper','eventMessage':secret+' DNS failure'})
        if argv[-1]=='--proxy':return 'ok','  HTTPEnable : 1\n  HTTPProxy : '+secret
        if argv[-1]=='--dns':return 'ok','resolver #1\n  port : 53541\n  domain : '+secret
        if argv[0].endswith('RouteClient'):
            assert kw['payload']==b'{"op":"status"}\n'
            return 'ok',json.dumps({'ok':True,'cleanupPending':True,'approvedDomains':[secret],'error':'ADAPTER_START_FAILED'})
        return 'недоступно',''
    with (patch.multiple(report,HOME=home,LOGS=logs,DATA=data,RES=res),
          patch.object(report,'run',side_effect=local_command),
          patch.object(trust,'official_output',side_effect=trust.Refused('OFFICIAL_INFO_FAILED'))):
        path=home/'diagnostics.txt'
        report.save(path)
        empty=path.read_text()
        assert report.MISSING in empty and 'OFFICIAL_INFO_FAILED' in empty
        assert 'ADAPTER_START_FAILED' in empty and '"category": "dns"' in empty
        write(data/'Selective/connection-events.previous.jsonl',{'component':'ssl','event':'gateway_recheck','time':100})
        event={'time':150,'attempt':2,'pid':42,'phase':'authenticating','component':'ssl','event':'failed',
               'code':'SITE_SAN_MISMATCH','failed_phase':'verifying_gateway','username':secret,'message':secret,
               'server_code':-123,'server_words':['office','mode','allocation','failed',secret,{'token':secret}]}
        history=data/'Selective/connection-events.jsonl'
        write(history,event)
        with history.open('a') as f:
            f.write('broken\n'+json.dumps({'event':secret,'errno':secret,'extra':{'login':secret}})+'\n')
        write(data/'ssl-status.json',{'checks':{'Авторизация':{'status':'error','result':secret}},
                                      'message':secret,'counters':{'out_packets':20,secret:1337},
                                      'httpsProbe':{'curlExit':60,'httpStatus':0,'tlsVerify':20,'method':'GET','host':secret,'stderr':secret}})
        write(data/'Selective/ConnectionDiagnostics/connections-1.jsonl',{'event':'tls_begin','peer':[secret,443],'phase':secret})
        write(data/'update-events.jsonl',{'event':'manual-check','appVersion':'0.3.13','errorDomain':secret})
        logsdir=logs/'Corporate VPN Router'
        logsdir.mkdir(parents=True)
        (logsdir/'launch-1.txt').write_text('2026-11-17T12:00:00Z main_entered /Users/'+secret+'\n')
        stage=home/'trial-input.json'
        stage.write_text(secret)
        (logsdir/'launch-link.txt').symlink_to(stage)
        (data/'Selective/last-session.txt').write_text(str(home))
        write(home/'Downloads/Router-SOTA-demo.txt',{})
        (home/'Downloads/Router-SOTA-demo.txt').write_text('[SOTA_ON]\ntcp_443_to_1.1.1.1=ok\nsecret='+secret)
        report.save(path)
        assert '"curlExit": 60' in path.read_text() and '"tlsVerify": 20' in path.read_text()
        text=path.read_text()
        for want in ('SITE_SAN_MISMATCH','verifying_gateway','tls_begin','manual-check','main_entered',
                     'tcp_443_to_1.1.1.1','DNS и SOCKS','Нечитаемых строк: 1','out_packets'):
            assert want in text,want
        assert text.index('SITE_SAN_MISMATCH')<text.index('## Попытки')
        assert secret not in text and str(home) not in text
        assert '"server_code": -123' in text and '"server_words": ["office", "mode", "allocation", "failed"]' in text
        assert stat.S_IMODE(path.stat().st_mode)==0o600
        failing = f'Conn {secret}:\n gw: {secret}:{1234}\n status: Connected\n active site: true\n (Connected) {secret}\n'
        with patch.object(trust,'DATA',data), patch.object(trust,'official_output',return_value=failing), patch.dict(os.environ,CVR_CONNECTION_ATTEMPT='17'):
            try: trust.official_info()
            except trust.ProfileFormatError as error: assert error.reason=='unsupported_gateway_address'
            else: raise AssertionError('invalid profile accepted')
            with history.open('a') as stream:
                stream.write(json.dumps(dict(time=200,pid=os.getppid(),attempt=17,component='ui',event='failure',
                    code='OFFICIAL_SITE_FORMAT_UNSUPPORTED',failed_phase='preparingRoutes'))+'\n')
            report.save(path)
            assert '"reason": "unsupported_gateway_address"' in path.read_text().split('## Попытки')[0]
        report.save(path)  # Current probe now fails independently, history still describes the actual refusal.
        result=path.read_text()
        assert '"profile_index": 1' in result and '"state": "Connected"' in result and '"active_site": "true"' in result
        assert secret not in result and secret not in (data/'last-checkpoint-refusal.json').read_text()
print('PASS: TXT with prior/current attempts, partial sources, typed redaction, summary and private file permissions')
