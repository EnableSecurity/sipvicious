import unittest
from unittest.mock import patch

from sipvicious.libs.svhelper import createTag
from sipvicious.libs.svhelper import parseHeader
from sipvicious.svwar import TakeASip


class SvwarFingerprintTests(unittest.TestCase):
    def make_scanner(self, method='REGISTER'):
        scanner = TakeASip(
            host='127.0.0.1',
            localport=0,
            method=method,
            guessmode=1,
            guessargs=(['1000'], 0, None, False),
            initialcheck=False,
        )
        self.addCleanup(scanner.sock.close)
        return scanner

    def test_register_fingerprint_uses_first_line_only(self):
        scanner = self.make_scanner()
        buff = (
            'SIP/2.0 401 Unauthorized\r\n'
            'WWW-Authenticate: Digest realm="example"\r\n'
            '\r\n'
        )
        parsed = scanner._parse_response(buff)
        self.assertEqual(scanner._response_fingerprint(buff, parsed), ('SIP/2.0 401 Unauthorized',))

    def test_invite_final_fingerprint_includes_reason_header(self):
        scanner = self.make_scanner(method='INVITE')
        buff = (
            'SIP/2.0 480 Temporarily Unavailable\r\n'
            'Reason: SIP;cause=806;text="USER_NOT_REGISTERED"\r\n'
            '\r\n'
        )
        parsed = scanner._parse_response(buff)
        self.assertEqual(
            scanner._response_fingerprint(buff, parsed),
            ('SIP/2.0 480 Temporarily Unavailable', 'SIP;cause=806;text="USER_NOT_REGISTERED"'),
        )

    def test_invite_scanner_enables_cancel_by_default(self):
        scanner = self.make_scanner(method='INVITE')
        self.assertTrue(scanner.enablecancel)

    def test_final_drain_timeout_has_conservative_floor(self):
        scanner = self.make_scanner(method='INVITE')
        self.assertEqual(scanner._final_drain_timeout(), 0.5)

    def test_final_drain_timeout_is_capped_by_socket_timeout(self):
        scanner = self.make_scanner(method='INVITE')
        scanner.selecttime = 1
        self.assertEqual(scanner._final_drain_timeout(), scanner.sock.gettimeout())

    def test_parse_header_accumulates_duplicate_record_route_headers(self):
        parsed = parseHeader(
            'SIP/2.0 200 OK\r\n'
            'Record-Route: <sip:edge.example;lr>\r\n'
            'Record-Route: <sip:core.example;lr>\r\n'
            '\r\n'
        )
        self.assertEqual(
            parsed['headers']['record-route'],
            ['<sip:edge.example;lr>', '<sip:core.example;lr>'],
        )

    def test_invite_provisional_response_is_detected(self):
        scanner = self.make_scanner(method='INVITE')
        parsed = scanner._parse_response(
            'SIP/2.0 183 Session Progress\r\n'
            'Content-Length: 0\r\n'
            '\r\n'
        )
        self.assertTrue(scanner._is_provisional(parsed))

    def test_invite_ringing_triggers_cancel_for_same_extension(self):
        scanner = self.make_scanner(method='INVITE')
        from_tag = createTag('1200').decode('ascii')
        payload = (
            'SIP/2.0 180 Ringing\r\n'
            'Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-123\r\n'
            'From: <sip:1200@example>;tag=%s\r\n'
            'To: <sip:1200@example>;tag=peer\r\n'
            'Call-ID: ring-123\r\n'
            'CSeq: 1 INVITE\r\n'
            '\r\n'
        ) % from_tag

        class FakeSock:
            def recvfrom(self, size):
                return payload.encode('utf-8'), ('127.0.0.1', 5060)

            def close(self):
                pass

        scanner.sock.close()
        scanner.sock = FakeSock()
        with patch.object(scanner, '_send_cancel') as send_cancel:
            scanner.getResponse()

        send_cancel.assert_called_once()
        parsed, extension = send_cancel.call_args[0]
        self.assertEqual(parsed['code'], 180)
        self.assertEqual(extension, '1200')

    def test_cancel_is_sent_once_per_call_id(self):
        scanner = self.make_scanner(method='INVITE')
        scanner.createRequest('INVITE', username='1200', cid='ring-123', cseq='1')
        parsed = {
            'headers': {
                'via': ['SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-123'],
                'from': ['<sip:1200@example>;tag=caller'],
                'to': ['<sip:1200@example>;tag=callee'],
                'call-id': ['ring-123'],
                'cseq': ['1 INVITE'],
            }
        }

        class FakeSock:
            def __init__(self):
                self.sent = []

            def sendto(self, data, dst):
                self.sent.append((data.decode('utf-8'), dst))
                return len(data)

            def close(self):
                pass

        scanner.sock.close()
        scanner.sock = FakeSock()
        scanner._send_cancel(parsed, '1200')
        scanner._send_cancel(parsed, '1200')

        self.assertEqual(len(scanner.sock.sent), 1)
        request, dst = scanner.sock.sent[0]
        self.assertIn('CANCEL sip:1200@127.0.0.1 SIP/2.0', request)
        self.assertIn('Call-ID: ring-123', request)
        self.assertIn('CSeq: 1 CANCEL', request)
        self.assertIn('To: "1200"<sip:1200@127.0.0.1>', request)
        self.assertNotIn('To: "1200"<sip:1200@127.0.0.1>;tag=', request)
        self.assertEqual(dst, ('127.0.0.1', 5060))

    def test_successful_invite_ack_and_bye_use_contact_and_route_set(self):
        scanner = self.make_scanner(method='INVITE')
        scanner.enableack = True
        scanner.createRequest('INVITE', username='2000', cid='call-1', cseq='1')
        transaction = scanner.invite_transactions['call-1']

        class FakeSock:
            def __init__(self, payload):
                self.payload = payload
                self.sent = []

            def recvfrom(self, size):
                return self.payload.encode('utf-8'), ('127.0.0.1', 5060)

            def sendto(self, data, dst):
                self.sent.append((data.decode('utf-8'), dst))
                return len(data)

            def close(self):
                pass

        payload = (
            'SIP/2.0 200 OK\r\n'
            'Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-server\r\n'
            'Record-Route: <sip:edge.example;lr>\r\n'
            'Record-Route: <sip:core.example;lr>\r\n'
            'From: %s\r\n'
            'To: "2000" <sip:2000@127.0.0.1>;tag=remote\r\n'
            'Call-ID: call-1\r\n'
            'CSeq: 1 INVITE\r\n'
            'Contact: <sip:2000-helper@127.0.0.1:5082>\r\n'
            '\r\n'
        ) % transaction['fromaddr']
        scanner.sock.close()
        scanner.sock = FakeSock(payload)
        scanner.getResponse()

        self.assertEqual(len(scanner.sock.sent), 2)
        ack_request, ack_dst = scanner.sock.sent[0]
        bye_request, bye_dst = scanner.sock.sent[1]
        self.assertIn('ACK sip:2000-helper@127.0.0.1:5082 SIP/2.0', ack_request)
        self.assertIn('Route: <sip:core.example;lr>', ack_request)
        self.assertIn('Route: <sip:edge.example;lr>', ack_request)
        self.assertIn('To: "2000" <sip:2000@127.0.0.1>;tag=remote', ack_request)
        self.assertIn('CSeq: 1 ACK', ack_request)
        self.assertIn('BYE sip:2000-helper@127.0.0.1:5082 SIP/2.0', bye_request)
        self.assertIn('Route: <sip:core.example;lr>', bye_request)
        self.assertIn('Route: <sip:edge.example;lr>', bye_request)
        self.assertIn('CSeq: 2 BYE', bye_request)
        self.assertEqual(ack_dst, ('127.0.0.1', 5060))
        self.assertEqual(bye_dst, ('127.0.0.1', 5060))

    def test_failed_invite_ack_uses_response_route_set(self):
        scanner = self.make_scanner(method='INVITE')
        scanner.enableack = True
        scanner.createRequest('INVITE', username='1019', cid='call-1', cseq='1')
        transaction = scanner.invite_transactions['call-1']

        class FakeSock:
            def __init__(self, payload):
                self.payload = payload
                self.sent = []

            def recvfrom(self, size):
                return self.payload.encode('utf-8'), ('127.0.0.1', 5060)

            def sendto(self, data, dst):
                self.sent.append((data.decode('utf-8'), dst))
                return len(data)

            def close(self):
                pass

        payload = (
            'SIP/2.0 480 Temporarily Unavailable\r\n'
            'Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-server\r\n'
            'Record-Route: <sip:edge.example;lr>\r\n'
            'Record-Route: <sip:core.example;lr>\r\n'
            'From: %s\r\n'
            'To: "1019" <sip:1019@127.0.0.1>;tag=remote\r\n'
            'Call-ID: call-1\r\n'
            'CSeq: 1 INVITE\r\n'
            '\r\n'
        ) % transaction['fromaddr']
        scanner.sock.close()
        scanner.sock = FakeSock(payload)
        scanner.getResponse()

        self.assertEqual(len(scanner.sock.sent), 1)
        ack_request, ack_dst = scanner.sock.sent[0]
        self.assertIn('ACK sip:1019@127.0.0.1 SIP/2.0', ack_request)
        self.assertIn('Route: <sip:core.example;lr>', ack_request)
        self.assertIn('Route: <sip:edge.example;lr>', ack_request)
        self.assertIn('CSeq: 1 ACK', ack_request)
        self.assertEqual(ack_dst, ('127.0.0.1', 5060))

    def test_provisional_invite_response_caches_route_set_for_final_ack(self):
        scanner = self.make_scanner(method='INVITE')
        scanner.enableack = True
        scanner.createRequest('INVITE', username='1019', cid='call-1', cseq='1')
        transaction = scanner.invite_transactions['call-1']

        class FakeSock:
            def __init__(self, payloads):
                self.payloads = list(payloads)
                self.sent = []

            def recvfrom(self, size):
                return self.payloads.pop(0).encode('utf-8'), ('127.0.0.1', 5060)

            def sendto(self, data, dst):
                self.sent.append((data.decode('utf-8'), dst))
                return len(data)

            def close(self):
                pass

        provisional = (
            'SIP/2.0 183 Session Progress\r\n'
            'Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-server\r\n'
            'Record-Route: <sip:edge.example;lr>\r\n'
            'Record-Route: <sip:core.example;lr>\r\n'
            'From: %s\r\n'
            'To: "1019" <sip:1019@127.0.0.1>;tag=remote\r\n'
            'Call-ID: call-1\r\n'
            'CSeq: 1 INVITE\r\n'
            '\r\n'
        ) % transaction['fromaddr']
        final = (
            'SIP/2.0 480 Temporarily Unavailable\r\n'
            'Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-server\r\n'
            'From: %s\r\n'
            'To: "1019" <sip:1019@127.0.0.1>;tag=remote\r\n'
            'Call-ID: call-1\r\n'
            'CSeq: 1 INVITE\r\n'
            '\r\n'
        ) % transaction['fromaddr']
        scanner.sock.close()
        scanner.sock = FakeSock([provisional, final])
        scanner.getResponse()
        scanner.getResponse()

        self.assertEqual(len(scanner.sock.sent), 1)
        ack_request, ack_dst = scanner.sock.sent[0]
        self.assertIn('ACK sip:1019@127.0.0.1 SIP/2.0', ack_request)
        self.assertIn('Route: <sip:core.example;lr>', ack_request)
        self.assertIn('Route: <sip:edge.example;lr>', ack_request)
        self.assertEqual(ack_dst, ('127.0.0.1', 5060))

    def test_duplicate_final_invite_response_is_ignored(self):
        scanner = self.make_scanner(method='INVITE')
        scanner.enableack = True
        scanner.createRequest('INVITE', username='2000', cid='call-1', cseq='1')
        transaction = scanner.invite_transactions['call-1']

        class FakeSock:
            def __init__(self, payloads):
                self.payloads = list(payloads)
                self.sent = []

            def recvfrom(self, size):
                return self.payloads.pop(0).encode('utf-8'), ('127.0.0.1', 5060)

            def sendto(self, data, dst):
                self.sent.append((data.decode('utf-8'), dst))
                return len(data)

            def close(self):
                pass

        payload = (
            'SIP/2.0 200 OK\r\n'
            'Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-server\r\n'
            'Record-Route: <sip:edge.example;lr>\r\n'
            'From: %s\r\n'
            'To: "2000" <sip:2000@127.0.0.1>;tag=remote\r\n'
            'Call-ID: call-1\r\n'
            'CSeq: 1 INVITE\r\n'
            'Contact: <sip:2000-helper@127.0.0.1:5082>\r\n'
            '\r\n'
        ) % transaction['fromaddr']

        scanner.sock.close()
        scanner.sock = FakeSock([payload, payload])
        scanner.getResponse()
        scanner.getResponse()

        self.assertEqual(len(scanner.sock.sent), 2)
        self.assertIn('call-1', scanner.seen_final_invites)
        self.assertNotIn('call-1', scanner.pending_invites)

    def test_create_request_tracks_pending_invites(self):
        scanner = self.make_scanner(method='INVITE')
        scanner.createRequest('INVITE', username='2000', cid='call-1', cseq='1')
        self.assertIn('call-1', scanner.pending_invites)

    def test_invite_internal_error_queues_retry_without_marking_extension_found(self):
        scanner = self.make_scanner(method='INVITE')
        scanner.BADUSER = ('SIP/2.0 480 Temporarily Unavailable', 'Q.850;cause=16;text="NORMAL_CLEARING"')
        from_tag = createTag('1028').decode('ascii')

        class FakeSock:
            def __init__(self, payload):
                self.payload = payload
                self.sent = []

            def recvfrom(self, size):
                return self.payload.encode('utf-8'), ('127.0.0.1', 5060)

            def sendto(self, data, dst):
                self.sent.append((data.decode('utf-8'), dst))
                return len(data)

            def close(self):
                pass

        payload = (
            'SIP/2.0 500 Maximum Calls In Progress\r\n'
            'Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-server\r\n'
            'From: <sip:1028@127.0.0.1>;tag=%s\r\n'
            'To: <sip:1028@127.0.0.1>;tag=remote\r\n'
            'Call-ID: call-1\r\n'
            'CSeq: 1 INVITE\r\n'
            '\r\n'
        ) % from_tag
        scanner.sock.close()
        scanner.sock = FakeSock(payload)
        scanner.getResponse()

        self.assertEqual(dict(scanner.resultauth), {})
        self.assertEqual(list(scanner.retry_extensions), ['1028'])
        self.assertEqual(scanner.retry_counts['1028'], 1)

    def test_incoming_bye_is_acknowledged(self):
        scanner = self.make_scanner(method='INVITE')

        class FakeSock:
            def __init__(self, payload):
                self.payload = payload
                self.sent = []

            def recvfrom(self, size):
                return self.payload.encode('utf-8'), ('127.0.0.1', 5060)

            def sendto(self, data, dst):
                self.sent.append((data.decode('utf-8'), dst))
                return len(data)

            def close(self):
                pass

        payload = (
            'BYE sip:scanner@127.0.0.1 SIP/2.0\r\n'
            'Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-server\r\n'
            'From: "peer" <sip:2000@127.0.0.1>;tag=remote\r\n'
            'To: "2000" <sip:2000@127.0.0.1>;tag=local\r\n'
            'Call-ID: call-1\r\n'
            'CSeq: 2 BYE\r\n'
            '\r\n'
        )
        scanner.sock.close()
        scanner.sock = FakeSock(payload)
        scanner.getResponse()

        self.assertEqual(len(scanner.sock.sent), 1)
        response, dst = scanner.sock.sent[0]
        self.assertIn('SIP/2.0 200 OK', response)
        self.assertIn('Call-ID: call-1', response)
        self.assertIn('CSeq: 2 BYE', response)
        self.assertEqual(dst, ('127.0.0.1', 5060))

    def test_unexpected_incoming_request_gets_481(self):
        scanner = self.make_scanner(method='INVITE')

        class FakeSock:
            def __init__(self, payload):
                self.payload = payload
                self.sent = []

            def recvfrom(self, size):
                return self.payload.encode('utf-8'), ('127.0.0.1', 5060)

            def sendto(self, data, dst):
                self.sent.append((data.decode('utf-8'), dst))
                return len(data)

            def close(self):
                pass

        payload = (
            'INFO sip:scanner@127.0.0.1 SIP/2.0\r\n'
            'Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-server\r\n'
            'From: "peer" <sip:2000@127.0.0.1>;tag=remote\r\n'
            'To: "2000" <sip:2000@127.0.0.1>;tag=local\r\n'
            'Call-ID: call-1\r\n'
            'CSeq: 3 INFO\r\n'
            '\r\n'
        )
        scanner.sock.close()
        scanner.sock = FakeSock(payload)
        scanner.getResponse()

        self.assertEqual(len(scanner.sock.sent), 1)
        response, dst = scanner.sock.sent[0]
        self.assertIn('SIP/2.0 481 Call/Transaction Does Not Exist', response)
        self.assertIn('Call-ID: call-1', response)
        self.assertIn('CSeq: 3 INFO', response)
        self.assertEqual(dst, ('127.0.0.1', 5060))


if __name__ == '__main__':
    unittest.main()
