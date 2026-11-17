import copy
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'Backend/Selective'))
from policy import validate_selective

base={'version':1,'sites':[{'domain':'work.example.invalid','scope':'tree'}],
      'beforeLogin':['login.example.invalid'],'ports':[443]}
assert validate_selective(base,'vpn.example.invalid')==base
cases=[]
c=copy.deepcopy(base);c['sites'][0]['scope']='exact';cases.append((c,None))
c=copy.deepcopy(base);c['beforeLogin']=['login.work.example.invalid'];cases.append((c,None))
cases.append((base,'gateway.work.example.invalid'))
c=copy.deepcopy(base);c['sites'][0]['domain']='198.18.0.0/16';cases.append((c,None))
for cfg,gateway in cases:
    try:validate_selective(cfg,gateway)
    except ValueError:pass
    else:raise AssertionError('unsupported scope accepted')
print('PASS supported tree policy; exact/covered exception/gateway/subnet rejected')
