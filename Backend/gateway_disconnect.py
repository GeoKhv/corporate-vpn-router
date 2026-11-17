"""Keep the server's numeric refusal and diagnostic words without its free text."""
import re

DISCONNECT_WORDS = frozenset("""
a access active address addresses allocate allocated allocation allowed already an and
another application applications are assigned assignment authentication authorization
available bad because been by can cannot certificate certificates check checking client
clients closed closing code concurrent configuration configured connect connected
connecting connection connections could denied deny detected device disabled disconnect
disconnected does due duplicate enabled endpoint error exceeded expired failed failure
for from gateway has have host in incompatible incorrect internal invalid ip is license
licenses licensing limit limited login logged machine mandatory maximum mode network no
not of office on one only operation out permission permissions please policy port
protocol reason reconnect rejected remote request required requires restricted security
server service session sessions should shutdown simultaneous ssl start stopped successful
supported system the this time timeout timed to token too transport tunnel type unable
unavailable unsupported up use used user users using valid validation version vpn was
were with without you your
ike ipsec identity challenge fingerprint fingerprints negotiation negotiate payload record exceeds
""".split())


def diagnostic_words(value):
    if not isinstance(value, str):
        return []
    # Tokens have to be standalone words. Embedded names, IDs, domains and
    # credential-shaped values are excluded as complete tokens.
    words = []
    for token in value.lower().split()[:100]:
        token = token.strip('.,;:!?"()')
        if token in DISCONNECT_WORDS:
            words.append(token)
    return words[:40]


def disconnect_details(reply):
    raw = reply.find('code')
    code = str(raw) if type(raw) in (str, int) else ''
    return {
        'server_code': int(code) if re.fullmatch(r'-?\d{1,9}', code) else None,
        'server_words': diagnostic_words(reply.find('message')),
    }
