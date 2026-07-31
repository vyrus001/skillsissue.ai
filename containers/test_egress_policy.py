import socket
import unittest

from egress_policy import (
    DestinationBlocked,
    allowed_port,
    resolve_public_host,
    sanitized_headers,
)


def resolver_with(*addresses):
    def resolve(_host, port, type=0):
        assert type == socket.SOCK_STREAM
        return [
            (socket.AF_INET6 if ":" in address else socket.AF_INET, type, 6, "", (address, port))
            for address in addresses
        ]

    return resolve


class EgressPolicyTests(unittest.TestCase):
    def test_only_public_resolutions_are_allowed(self):
        self.assertEqual(
            resolve_public_host(
                "downloads.example", 443, resolver_with("93.184.216.34")
            ),
            "93.184.216.34",
        )
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "192.168.1.1",
            "::1",
            "fe80::1",
            "fd00::1",
        ]:
            with self.subTest(address=address), self.assertRaises(DestinationBlocked):
                resolve_public_host("downloads.example", 443, resolver_with(address))

    def test_mixed_public_private_dns_is_blocked(self):
        with self.assertRaises(DestinationBlocked):
            resolve_public_host(
                "rebinding.example",
                443,
                resolver_with("93.184.216.34", "127.0.0.1"),
            )

    def test_local_names_and_unsupported_ports_are_blocked(self):
        for host in ["localhost", "metadata.internal", "printer.local", "singlelabel"]:
            with self.subTest(host=host), self.assertRaises(DestinationBlocked):
                resolve_public_host(host, 443, resolver_with("93.184.216.34"))
        self.assertTrue(allowed_port("http", 80))
        self.assertTrue(allowed_port("https", 443))
        self.assertFalse(allowed_port("https", 8443))

    def test_sensitive_and_hop_headers_are_not_persisted(self):
        headers = sanitized_headers(
            [
                ("Authorization", "secret"),
                ("Cookie", "secret"),
                ("Connection", "x-remove"),
                ("X-Remove", "value"),
                ("Content-Type", "application/octet-stream"),
            ]
        )
        self.assertEqual(headers, [["content-type", "application/octet-stream"]])


if __name__ == "__main__":
    unittest.main()
