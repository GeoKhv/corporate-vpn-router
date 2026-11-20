from pathlib import Path
import socket
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'Backend' / 'Selective'))
from system_dns_check import check, confirmed


class SystemDNSTest(unittest.TestCase):
    def test_system_and_router(self):
        router = {'198.18.75.2', 'fdc7:7652:9a10:75::2'}
        def missing(_):
            raise socket.gaierror(socket.EAI_NONAME, 'fixture')
        for expected, system, outcome in [
                (router, lambda _: {'198.18.75.2'}, 'ok'),
                (router, missing, 'missing'),
                (router, lambda _: {'198.18.75.2', '192.0.2.1'}, 'different'),
                (set(), lambda _: self.fail('no Router response'), 'router_unavailable')]:
            self.assertEqual(check('work.invalid', lambda _: expected, system), outcome)

    def test_requires_repeated_failure(self):
        for responses, expected in [(['missing', 'ok'], 'ok'), (['missing', 'missing'], 'missing'),
                                    (['different', 'missing'], 'inconclusive')]:
            sequence = iter(responses)
            self.assertEqual(confirmed('work.invalid', lambda _: next(sequence), lambda _: None), expected)


if __name__ == '__main__':
    unittest.main()
