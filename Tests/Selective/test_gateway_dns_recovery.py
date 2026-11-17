"""Exercise the gateway check with the DNS outcomes seen on macOS."""
from pathlib import Path
import socket
import sys
import threading
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(sys.argv.pop(1)).resolve()))
import trust


class GatewayDNS(unittest.TestCase):
    host = 'gateway.example.invalid'
    ip = '192.0.2.10'

    def setUp(self):
        self.native = self.patch(trust, 'official_info', return_value=(self.host, self.ip, 'Idle'))
        self.lookup = self.patch(socket, 'getaddrinfo')
        self.patch(trust, 'GATEWAY_DNS_RETRY_DELAY', 0)
        self.report = Mock()

    def patch(self, obj, name, *args, **kwargs):
        p = patch.object(obj, name, *args, **kwargs)
        self.addCleanup(p.stop)
        return p.start()

    def site(self):
        return trust.site(report_dns=self.report)

    def test_recovers_after_darwin_noname(self):
        self.lookup.side_effect = [socket.gaierror(socket.EAI_NONAME, 'fixture'),
                                   [(0, 0, 0, '', (self.ip, 443))]]
        self.assertEqual(self.site(), (self.host, self.ip))
        self.assertEqual([c.args[0] for c in self.report.call_args_list],
                         ['gateway_dns_lookup', 'gateway_dns_retry', 'gateway_dns_verified'])
        for call in self.lookup.call_args_list:
            self.assertEqual(call.args, (self.host, 443, socket.AF_INET, socket.SOCK_STREAM))

    def test_unresolved_ipv4(self):
        self.lookup.side_effect = socket.gaierror(socket.EAI_AGAIN, 'fixture')
        with self.assertRaisesRegex(trust.Refused, '^GATEWAY_DNS_UNRESOLVED$') as failure:
            self.site()
        self.assertEqual(failure.exception.__cause__.errno, socket.EAI_AGAIN)
        self.assertEqual(self.lookup.call_count, 2)

    def test_permanent_error(self):
        self.lookup.side_effect = socket.gaierror(socket.EAI_FAIL, 'fixture')
        with self.assertRaisesRegex(trust.Refused, '^GATEWAY_DNS_UNRESOLVED$'):
            self.site()
        self.assertEqual(self.lookup.call_count, 1)

    def test_hung_lookup_cannot_delay_login_indefinitely(self):
        release = threading.Event()
        self.addCleanup(release.set)
        self.patch(trust, 'GATEWAY_DNS_BUDGET', 0.06)
        self.lookup.side_effect = lambda *args: release.wait(5)
        start = time.monotonic()
        with self.assertRaisesRegex(trust.Refused, '^GATEWAY_DNS_TIMEOUT$'):
            self.site()
        self.assertLess(time.monotonic() - start, 1)
        self.assertEqual(self.lookup.call_count, 1)

    def test_dns_answer_must_contain_native_address(self):
        self.lookup.return_value = [(0, 0, 0, '', ('192.0.2.20', 443))]
        with self.assertRaisesRegex(trust.Refused, '^SITE_ADDRESS_MISMATCH$'):
            self.site()
        self.assertEqual(self.lookup.call_count, 1)

    def test_native_site_changed_during_recovery(self):
        self.native.side_effect = [(self.host, self.ip, 'Idle'), (self.host, '192.0.2.20', 'Idle')]
        self.lookup.side_effect = [socket.gaierror(socket.EAI_AGAIN, 'fixture'),
                                   [(0, 0, 0, '', (self.ip, 443))]]
        with self.assertRaisesRegex(trust.Refused, '^OFFICIAL_SELECTION_CHANGED$'):
            self.site()


if __name__ == '__main__':
    unittest.main()
