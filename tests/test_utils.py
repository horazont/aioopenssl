import contextlib
import unittest
import unittest.mock

import OpenSSL.SSL

import aioopenssl.utils as utils


class TestSendWrap(unittest.TestCase):
    def setUp(self):
        self.default_send = lambda x: len(x)

        self.sock = unittest.mock.Mock(["send"])
        self.sock.send.side_effect = self.default_send
        self.ww = utils.SendWrap(self.sock)

    def test_send_calls_send(self):
        data = unittest.mock.sentinel.data

        self.sock.send.side_effect = None
        self.sock.send.return_value = unittest.mock.sentinel.send_result

        with contextlib.ExitStack() as stack:
            bytes_ = stack.enter_context(
                unittest.mock.patch("aioopenssl.utils.bytes")
            )

            result = self.ww.send(data)

        bytes_.assert_called_once_with(data)

        self.sock.send.assert_called_once_with(bytes_())

        self.assertEqual(
            result,
            unittest.mock.sentinel.send_result,
        )

    def test_send_propagates_exceptions_from_send(self):
        data = bytearray()

        self.sock.send.side_effect = OpenSSL.SSL.Error

        with self.assertRaises(OpenSSL.SSL.Error):
            self.ww.send(data)

    def test_send_propagates_want_read_from_send(self):
        data = bytearray()

        self.sock.send.side_effect = OpenSSL.SSL.WantReadError

        with self.assertRaises(OpenSSL.SSL.WantReadError):
            self.ww.send(data)

    def test_send_propagates_want_send_from_send(self):
        data = bytearray()

        self.sock.send.side_effect = OpenSSL.SSL.WantWriteError

        with self.assertRaises(OpenSSL.SSL.WantWriteError):
            self.ww.send(data)

    def test_send_after_want_send_passes_cached_bytes(self):
        data = unittest.mock.sentinel.data

        with contextlib.ExitStack() as stack:
            bytes_ = stack.enter_context(
                unittest.mock.patch("aioopenssl.utils.bytes")
            )

            self.sock.send.side_effect = OpenSSL.SSL.WantWriteError

            with self.assertRaises(OpenSSL.SSL.WantWriteError):
                self.ww.send(data)

            bytes_.assert_called_once_with(data)
            self.sock.send.assert_called_once_with(bytes_())

            bytes_.reset_mock()
            self.sock.send.reset_mock()

            self.sock.send.side_effect = None
            self.sock.send.return_value = unittest.mock.sentinel.send_result

            result = self.ww.send(data)

        bytes_.assert_not_called()
        self.sock.send.assert_called_once_with(bytes_())

        self.assertEqual(result, unittest.mock.sentinel.send_result)

    def test_send_after_want_send_works_normally(self):
        data = unittest.mock.sentinel.data
        data2 = unittest.mock.sentinel.data2

        with contextlib.ExitStack() as stack:
            bytes_ = stack.enter_context(
                unittest.mock.patch("aioopenssl.utils.bytes")
            )

            self.sock.send.side_effect = OpenSSL.SSL.WantWriteError

            with self.assertRaises(OpenSSL.SSL.WantWriteError):
                self.ww.send(data)

            bytes_.assert_called_once_with(data)
            self.sock.send.assert_called_once_with(bytes_())

            bytes_.reset_mock()
            self.sock.send.reset_mock()

            self.sock.send.side_effect = None
            self.sock.send.return_value = unittest.mock.sentinel.send_result1

            result1 = self.ww.send(data)

            bytes_.assert_not_called()
            self.sock.send.assert_called_once_with(bytes_())

            bytes_.reset_mock()
            bytes_.return_value = unittest.mock.sentinel.new_bytes
            self.sock.send.reset_mock()

            self.sock.send.return_value = unittest.mock.sentinel.send_result2

            result2 = self.ww.send(data2)

            bytes_.assert_called_once_with(data2)
            self.sock.send.assert_called_once_with(
                unittest.mock.sentinel.new_bytes
            )

            bytes_.reset_mock()
            self.sock.send.reset_mock()

        self.assertEqual(result1, unittest.mock.sentinel.send_result1)
        self.assertEqual(result2, unittest.mock.sentinel.send_result2)

    def test_send_after_want_send_rejects_subsequent_call_if_different_buffer(self):  # NOQA
        data = unittest.mock.sentinel.data
        data2 = unittest.mock.sentinel.data2

        with contextlib.ExitStack() as stack:
            bytes_ = stack.enter_context(
                unittest.mock.patch("aioopenssl.utils.bytes")
            )

            self.sock.send.side_effect = OpenSSL.SSL.WantWriteError

            with self.assertRaises(OpenSSL.SSL.WantWriteError):
                self.ww.send(data)

            bytes_.assert_called_once_with(data)
            self.sock.send.assert_called_once_with(bytes_())

            bytes_.reset_mock()
            self.sock.send.reset_mock()

            self.sock.send.side_effect = None
            self.sock.send.return_value = unittest.mock.sentinel.send_result1

            with self.assertRaisesRegex(
                    ValueError,
                    "this looks like a mistake: the previous send received a "
                    "different buffer object"):
                self.ww.send(data2)

            bytes_.assert_not_called()
            self.sock.send.assert_not_called()

    def test_send_after_want_read_passes_cached_bytes(self):
        data = unittest.mock.sentinel.data

        with contextlib.ExitStack() as stack:
            bytes_ = stack.enter_context(
                unittest.mock.patch("aioopenssl.utils.bytes")
            )

            self.sock.send.side_effect = OpenSSL.SSL.WantReadError

            with self.assertRaises(OpenSSL.SSL.WantReadError):
                self.ww.send(data)

            bytes_.assert_called_once_with(data)
            self.sock.send.assert_called_once_with(bytes_())

            bytes_.reset_mock()
            self.sock.send.reset_mock()

            self.sock.send.side_effect = None
            self.sock.send.return_value = unittest.mock.sentinel.send_result

            result = self.ww.send(data)

        bytes_.assert_not_called()
        self.sock.send.assert_called_once_with(bytes_())

        self.assertEqual(result, unittest.mock.sentinel.send_result)

    def test_send_after_want_read_works_normally(self):
        data = unittest.mock.sentinel.data
        data2 = unittest.mock.sentinel.data2

        with contextlib.ExitStack() as stack:
            bytes_ = stack.enter_context(
                unittest.mock.patch("aioopenssl.utils.bytes")
            )

            self.sock.send.side_effect = OpenSSL.SSL.WantReadError

            with self.assertRaises(OpenSSL.SSL.WantReadError):
                self.ww.send(data)

            bytes_.assert_called_once_with(data)
            self.sock.send.assert_called_once_with(bytes_())

            bytes_.reset_mock()
            self.sock.send.reset_mock()

            self.sock.send.side_effect = None
            self.sock.send.return_value = unittest.mock.sentinel.send_result1

            result1 = self.ww.send(data)

            bytes_.assert_not_called()
            self.sock.send.assert_called_once_with(bytes_())

            bytes_.reset_mock()
            bytes_.return_value = unittest.mock.sentinel.new_bytes
            self.sock.send.reset_mock()

            self.sock.send.return_value = unittest.mock.sentinel.send_result2

            result2 = self.ww.send(data2)

            bytes_.assert_called_once_with(data2)
            self.sock.send.assert_called_once_with(
                unittest.mock.sentinel.new_bytes
            )

            bytes_.reset_mock()
            self.sock.send.reset_mock()

        self.assertEqual(result1, unittest.mock.sentinel.send_result1)
        self.assertEqual(result2, unittest.mock.sentinel.send_result2)

    def test_send_after_want_read_rejects_subsequent_call_if_different_buffer(self):  # NOQA
        data = unittest.mock.sentinel.data
        data2 = unittest.mock.sentinel.data2

        with contextlib.ExitStack() as stack:
            bytes_ = stack.enter_context(
                unittest.mock.patch("aioopenssl.utils.bytes")
            )

            self.sock.send.side_effect = OpenSSL.SSL.WantReadError

            with self.assertRaises(OpenSSL.SSL.WantReadError):
                self.ww.send(data)

            bytes_.assert_called_once_with(data)
            self.sock.send.assert_called_once_with(bytes_())

            bytes_.reset_mock()
            self.sock.send.reset_mock()

            self.sock.send.side_effect = None
            self.sock.send.return_value = unittest.mock.sentinel.send_result1

            with self.assertRaisesRegex(
                    ValueError,
                    "this looks like a mistake: the previous send received a "
                    "different buffer object"):
                self.ww.send(data2)

            bytes_.assert_not_called()
            self.sock.send.assert_not_called()

    def test_send_with_several_want_read_send_errors(self):
        data = unittest.mock.sentinel.data
        data2 = unittest.mock.sentinel.data2

        with contextlib.ExitStack() as stack:
            bytes_ = stack.enter_context(
                unittest.mock.patch("aioopenssl.utils.bytes")
            )

            self.sock.send.side_effect = OpenSSL.SSL.WantReadError

            with self.assertRaises(OpenSSL.SSL.WantReadError):
                self.ww.send(data)

            bytes_.assert_called_once_with(data)
            self.sock.send.assert_called_once_with(bytes_())

            bytes_.reset_mock()
            self.sock.send.reset_mock()

            self.sock.send.side_effect = OpenSSL.SSL.WantWriteError

            with self.assertRaises(OpenSSL.SSL.WantWriteError):
                self.ww.send(data)

            bytes_.assert_not_called()
            self.sock.send.assert_called_once_with(bytes_())

            bytes_.reset_mock()
            self.sock.send.reset_mock()

            self.sock.send.side_effect = OpenSSL.SSL.WantWriteError

            with self.assertRaises(OpenSSL.SSL.WantWriteError):
                self.ww.send(data)

            bytes_.assert_not_called()
            self.sock.send.assert_called_once_with(bytes_())

            bytes_.reset_mock()
            self.sock.send.reset_mock()

            self.sock.send.side_effect = None
            self.sock.send.return_value = unittest.mock.sentinel.send_result1

            result1 = self.ww.send(data)

            bytes_.assert_not_called()
            self.sock.send.assert_called_once_with(bytes_())

            bytes_.reset_mock()
            bytes_.return_value = unittest.mock.sentinel.new_bytes
            self.sock.send.reset_mock()

            self.sock.send.return_value = unittest.mock.sentinel.send_result2

            result2 = self.ww.send(data2)

            bytes_.assert_called_once_with(data2)
            self.sock.send.assert_called_once_with(
                unittest.mock.sentinel.new_bytes
            )

            bytes_.reset_mock()
            self.sock.send.reset_mock()

        self.assertEqual(result1, unittest.mock.sentinel.send_result1)
        self.assertEqual(result2, unittest.mock.sentinel.send_result2)
