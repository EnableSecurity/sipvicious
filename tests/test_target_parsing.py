import unittest

from sipvicious.libs.svhelper import normalize_svmap_ipv6_target, parse_scan_target


class ParseScanTargetTests(unittest.TestCase):
    def test_plain_ipv6_literal_uses_default_port(self):
        host, port = parse_scan_target("2001:db8::10", 5060)
        self.assertEqual(host, "2001:db8::10")
        self.assertEqual(port, 5060)

    def test_plain_bracketed_ipv6_literal_with_port(self):
        host, port = parse_scan_target("[2001:db8::10]:5080", 5060)
        self.assertEqual(host, "2001:db8::10")
        self.assertEqual(port, 5080)

    def test_udp_uri_ipv6_literal_with_port(self):
        host, port = parse_scan_target("udp://[2001:db8::10]:5080", 5060)
        self.assertEqual(host, "2001:db8::10")
        self.assertEqual(port, 5080)

    def test_plain_hostname_with_port(self):
        host, port = parse_scan_target("pbx.example.org:5070", 5060)
        self.assertEqual(host, "pbx.example.org")
        self.assertEqual(port, 5070)

    def test_unsupported_scheme_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "not supported"):
            parse_scan_target("tcp://[2001:db8::10]:5060", 5060)

    def test_duplicate_port_definition_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Please use only one"):
            parse_scan_target("[2001:db8::10]:5080", 5070)

    def test_svmap_accepts_bracketed_ipv6_literal(self):
        self.assertEqual(
            normalize_svmap_ipv6_target("[2001:db8::10]"),
            "2001:db8::10",
        )

    def test_svmap_rejects_uri_syntax(self):
        with self.assertRaisesRegex(ValueError, "not supported in svmap"):
            normalize_svmap_ipv6_target("udp://[2001:db8::10]:5060")

    def test_svmap_rejects_embedded_port(self):
        with self.assertRaisesRegex(ValueError, "Use -p"):
            normalize_svmap_ipv6_target("[2001:db8::10]:5060")


if __name__ == "__main__":
    unittest.main()
