from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'Backend'))
from gateway_disconnect import disconnect_details, diagnostic_words
class Reply:
    def __init__(self, **fields):self.fields=fields
    def find(self,key):return self.fields.get(key)
secret='USER_PRIVATE_BEARER_568942'
r=disconnect_details(Reply(code='-123',message='Office mode IP allocation failed for '+secret+' at host.example 192.0.2.1'))
assert r=={'server_code':-123,'server_words':['office','mode','ip','allocation','failed','for']},r
for value in (None,True,{},[],secret,'123 '+secret,'1234567890'):
    assert disconnect_details(Reply(code=value,message=value))=={'server_code':None,'server_words':[]}
assert disconnect_details(Reply(code=0))['server_code']==0
assert len(diagnostic_words('failed '*120))==40
print('PASS refusal code and bounded diagnostic vocabulary; no free text, identity, address or token')
