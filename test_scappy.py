import importlib
import unittest
from unittest.mock import MagicMock, patch

import scappy


class MainTests(unittest.TestCase):
    def test_import_does_not_prompt_for_input(self):
        with patch(
            "builtins.input",
            side_effect=AssertionError("module import must not prompt"),
        ):
            importlib.reload(scappy)

    def test_builds_ipv4_icmp_packet(self):
        packet = scappy.build_packet("192.0.2.1", "icmp")

        self.assertTrue(packet.haslayer(scappy.IP))
        self.assertTrue(packet.haslayer(scappy.ICMP))

    def test_builds_ipv6_icmp_packet(self):
        packet = scappy.build_packet("2001:db8::1", "icmp")

        self.assertTrue(packet.haslayer(scappy.IPv6))
        self.assertTrue(packet.haslayer(scappy.ICMPv6EchoRequest))

    def test_builds_ipv6_tcp_packet(self):
        packet = scappy.build_packet("2001:db8::1", "tcp")

        self.assertTrue(packet.haslayer(scappy.IPv6))
        self.assertTrue(packet.haslayer(scappy.TCP))
        self.assertEqual(packet[scappy.TCP].dport, 80)
        self.assertEqual(packet[scappy.TCP].flags, "S")

    def test_builds_ipv4_tcp_packet(self):
        packet = scappy.build_packet("192.0.2.1", "tcp")

        self.assertTrue(packet.haslayer(scappy.IP))
        self.assertTrue(packet.haslayer(scappy.TCP))
        self.assertEqual(packet[scappy.TCP].dport, 80)
        self.assertEqual(packet[scappy.TCP].flags, "S")

    def test_build_packet_rejects_unsupported_protocol(self):
        with self.assertRaisesRegex(ValueError, "Unsupported protocol: udp"):
            scappy.build_packet("192.0.2.1", "udp")

    def test_icmpv6_response_is_classified_correctly(self):
        response = scappy.ICMPv6EchoReply()

        with patch("scappy.logger.info") as log_info:
            scappy.handle_response("2001:db8::1", response)

        log_info.assert_any_call("Received %s response from %s:", "ICMP", "2001:db8::1")

    def test_tcp_response_is_classified_correctly(self):
        response = scappy.TCP()

        with patch("scappy.logger.info") as log_info:
            scappy.handle_response("192.0.2.1", response)

        log_info.assert_any_call("Received %s response from %s:", "TCP", "192.0.2.1")

    def test_unexpected_response_is_classified_correctly(self):
        response = scappy.IP()

        with patch("scappy.logger.info") as log_info:
            scappy.handle_response("192.0.2.1", response)

        log_info.assert_any_call(
            "Received %s response from %s:", "unexpected", "192.0.2.1"
        )

    def test_missing_target_shows_argparse_error(self):
        with self.assertRaises(SystemExit) as exc:
            scappy.main([])

        self.assertEqual(exc.exception.code, 2)

    @patch("scappy.sr1")
    def test_invalid_target_is_rejected_before_sending(self, send):
        with self.assertRaises(SystemExit) as exc:
            scappy.main(["not-an-ip", "icmp", "--yes"])

        self.assertEqual(exc.exception.code, 2)
        send.assert_not_called()

    def test_unknown_mode_is_rejected(self):
        with self.assertRaises(SystemExit) as exc:
            scappy.main(["192.0.2.1", "udp"])

        self.assertEqual(exc.exception.code, 2)

    @patch("scappy.sr1", return_value=None)
    @patch("scappy.ICMP")
    @patch("scappy.IP")
    @patch("scappy.logger.info")
    def test_direct_icmp_mode_requires_confirmation(
        self, log_info, ip_layer, icmp_layer, send
    ):
        packet = MagicMock()
        ip_layer.return_value.__truediv__.return_value = packet

        with patch("builtins.input", return_value="y") as prompt:
            scappy.main(["192.0.2.1", "icmp"])

        prompt.assert_called_once()
        ip_layer.assert_called_once_with(dst="192.0.2.1")
        icmp_layer.assert_called_once_with()
        send.assert_called_once_with(packet, timeout=2, verbose=False)
        log_info.assert_any_call("Sending ICMP packet to %s...", "192.0.2.1")

    @patch("scappy.sr1")
    def test_yes_flag_skips_confirmation(self, send):
        packet = MagicMock()
        with patch("scappy.build_packet", return_value=packet), patch(
            "builtins.input"
        ) as prompt:
            scappy.main(["192.0.2.1", "icmp", "--yes"])

        prompt.assert_not_called()
        send.assert_called_once_with(packet, timeout=2, verbose=False)

    @patch("scappy.sr1")
    def test_declining_confirmation_does_not_send(self, send):
        with patch("builtins.input", return_value="n"):
            scappy.main(["192.0.2.1", "tcp"])

        send.assert_not_called()

    @patch("scappy.send_packet")
    def test_confirmation_eof_cancels_without_sending(self, send):
        with patch("builtins.input", side_effect=EOFError):
            scappy.main(["192.0.2.1", "icmp"])

        send.assert_not_called()

    def test_confirmation_keyboard_interrupt_cancels_without_sending(self):
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            self.assertFalse(scappy.confirm_send())

    @patch("scappy.logger.error")
    @patch("scappy.sr1", side_effect=PermissionError("raw socket unavailable"))
    def test_raw_socket_error_is_reported_without_traceback(self, _send, log_error):
        success = scappy.send_packet("192.0.2.1", "icmp")

        self.assertFalse(success)
        log_error.assert_called_once()
        self.assertIn("Packet send failed", log_error.call_args.args[0])

    @patch("scappy.logger.error")
    @patch(
        "scappy.sr1",
        side_effect=scappy.Scapy_Exception("Scapy could not send packet"),
    )
    def test_scapy_error_returns_failure(self, _send, log_error):
        self.assertFalse(scappy.send_packet("192.0.2.1", "icmp"))
        log_error.assert_called_once()

    @patch("scappy.send_packet", return_value=False)
    def test_cli_returns_nonzero_when_packet_send_fails(self, _send):
        with patch("builtins.input", return_value="y"):
            self.assertEqual(scappy.main(["192.0.2.1", "icmp"]), 1)

    @patch("scappy.sr1")
    @patch("scappy.TCP")
    @patch("scappy.IP")
    def test_tcp_mode_builds_syn_packet(self, ip_layer, tcp_layer, send):
        packet = MagicMock()
        ip_layer.return_value.__truediv__.return_value = packet

        with patch("builtins.input", return_value="y"):
            scappy.main(["192.0.2.1", "TCP"])

        ip_layer.assert_called_once_with(dst="192.0.2.1")
        tcp_layer.assert_called_once_with(dport=80, flags="S")
        ip_layer.return_value.__truediv__.assert_called_once_with(
            tcp_layer.return_value
        )
        send.assert_called_once_with(packet, timeout=2, verbose=False)

    @patch("scappy.send_packet")
    def test_menu_retries_invalid_choice_and_sends_selected_protocol(self, send):
        with patch(
            "builtins.input", side_effect=["letters", "3", "2", "y"]
        ) as prompt:
            scappy.send_packet_interactive("192.0.2.1")

        self.assertEqual(prompt.call_count, 4)
        send.assert_called_once_with("192.0.2.1", "icmp")

    @patch("scappy.send_packet")
    def test_menu_sends_tcp_when_first_option_is_selected(self, send):
        with patch("builtins.input", side_effect=["1", "y"]):
            scappy.send_packet_interactive("192.0.2.1")

        send.assert_called_once_with("192.0.2.1", "tcp")

    @patch("scappy.send_packet")
    def test_menu_decline_cancels_without_sending(self, send):
        with patch("builtins.input", side_effect=["2", "n"]):
            scappy.send_packet_interactive("192.0.2.1")

        send.assert_not_called()

    @patch("scappy.main_banner")
    @patch("scappy.send_packet")
    def test_default_mode_shows_splash_and_uses_menu(self, send, show_banner):
        with patch("builtins.input", side_effect=["2", "y"]):
            status = scappy.main(["192.0.2.1"])

        self.assertEqual(status, 0)
        show_banner.assert_called_once_with()
        send.assert_called_once_with("192.0.2.1", "icmp")

    @patch("scappy.send_packet")
    def test_menu_quit_exits_without_sending(self, send):
        with patch("builtins.input", return_value="q"):
            self.assertTrue(scappy.send_packet_interactive("192.0.2.1"))

        send.assert_not_called()

    @patch("scappy.send_packet")
    def test_menu_cancels_when_input_reaches_eof(self, send):
        with patch("builtins.input", side_effect=EOFError):
            scappy.send_packet_interactive("192.0.2.1")

        send.assert_not_called()

    @patch("scappy.send_packet")
    def test_confirmation_retries_invalid_answer(self, send):
        with patch("builtins.input", side_effect=["maybe", "Y"]):
            scappy.main(["192.0.2.1", "icmp"])

        send.assert_called_once_with("192.0.2.1", "icmp")

    @patch("scappy.sr1", return_value=None)
    @patch("scappy.ICMP")
    @patch("scappy.IP")
    @patch("scappy.logger.warning")
    def test_no_response_is_logged(self, log_warning, ip_layer, _icmp, _send):
        ip_layer.return_value.__truediv__.return_value = MagicMock()
        scappy.send_packet("192.0.2.1", "icmp")

        log_warning.assert_called_once_with(
            "No response received from %s within timeout window.", "192.0.2.1"
        )

    @patch("scappy.send_packet")
    def test_traceroute_mode_warns_that_it_is_a_single_probe(self, send):
        with patch("builtins.input", return_value="y"), patch(
            "scappy.logger.info"
        ) as log_info:
            scappy.main(["192.0.2.1", "traceroute"])

        log_info.assert_any_call(
            "Traceroute mode currently sends one ICMP probe; it does not trace hops."
        )
        send.assert_called_once_with("192.0.2.1", "icmp")


if __name__ == "__main__":
    unittest.main()
