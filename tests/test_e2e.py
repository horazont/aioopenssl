import asyncio
import functools
import os
import pathlib
import ssl
import unittest
import unittest.mock

import OpenSSL.SSL

import aioopenssl


PORT = int(os.environ.get("AIOOPENSSL_TEST_PORT", "12345"))
KEYFILE = pathlib.Path(__file__).parent / "ssl.pem"


def blocking(meth):
    @functools.wraps(meth)
    def wrapper(*args, **kwargs):
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(
            asyncio.wait_for(meth(*args, **kwargs), 1)
        )

    return wrapper


class TestSSLConnection(unittest.TestCase):
    @blocking
    @asyncio.coroutine
    def setUp(self):
        self.loop = asyncio.get_event_loop()
        self.server_ctx = ssl.create_default_context(
            ssl.Purpose.CLIENT_AUTH
        )

        self.server_ctx.load_cert_chain(str(KEYFILE))

        self.server = yield from asyncio.start_server(
            self._server_accept,
            host="127.0.0.1",
            port=PORT,
            ssl=self.server_ctx,
        )
        self.inbound_queue = asyncio.Queue()

    @blocking
    @asyncio.coroutine
    def tearDown(self):
        self.server.close()
        while not self.inbound_queue.empty():
            reader, writer = yield from self.inbound_queue.get()
            writer.close()
        yield from self.server.wait_closed()

    def _server_accept(self, reader, writer):
        self.inbound_queue.put_nowait(
            (reader, writer)
        )

    def _stream_reader_proto(self):
        reader = asyncio.StreamReader(loop=self.loop)
        proto = asyncio.StreamReaderProtocol(reader)
        return proto

    def _connect(self, *args, **kwargs):
        transport, reader_proto = yield from aioopenssl.create_starttls_connection(
            asyncio.get_event_loop(),
            self._stream_reader_proto,
            *args,
            **kwargs
        )
        reader = reader_proto._stream_reader
        writer = asyncio.StreamWriter(transport, reader_proto, reader,
                                      self.loop)
        return transport, reader, writer

    @blocking
    @asyncio.coroutine
    def test_send_and_receive_data(self):
        _, c_reader, c_writer = yield from self._connect(
            host="127.0.0.1",
            port=PORT,
            ssl_context_factory=lambda transport: OpenSSL.SSL.Context(
                OpenSSL.SSL.SSLv23_METHOD
            ),
            server_hostname="localhost",
            use_starttls=False,
        )

        s_reader, s_writer = yield from self.inbound_queue.get()

        c_writer.write(b"foobar")
        s_writer.write(b"fnord")

        yield from asyncio.gather(s_writer.drain(), c_writer.drain())

        c_read, s_read = yield from asyncio.gather(
            c_reader.readexactly(5),
            s_reader.readexactly(6),
        )

        self.assertEqual(
            s_read,
            b"foobar"
        )

        self.assertEqual(
            c_read,
            b"fnord"
        )

    @blocking
    @asyncio.coroutine
    def test_send_large_data(self):
        _, c_reader, c_writer = yield from self._connect(
            host="127.0.0.1",
            port=PORT,
            ssl_context_factory=lambda transport: OpenSSL.SSL.Context(
                OpenSSL.SSL.SSLv23_METHOD
            ),
            server_hostname="localhost",
            use_starttls=False,
        )

        s_reader, s_writer = yield from self.inbound_queue.get()

        data = bytearray(2**17)

        c_writer.write(data)
        s_writer.write(b"foobar")

        yield from asyncio.gather(s_writer.drain(), c_writer.drain())

        c_read, s_read = yield from asyncio.gather(
            c_reader.readexactly(6),
            s_reader.readexactly(len(data)),
        )

        self.assertEqual(
            s_read,
            data,
        )

        self.assertEqual(
            c_read,
            b"foobar",
        )

    @blocking
    @asyncio.coroutine
    def test_recv_large_data(self):
        _, c_reader, c_writer = yield from self._connect(
            host="127.0.0.1",
            port=PORT,
            ssl_context_factory=lambda transport: OpenSSL.SSL.Context(
                OpenSSL.SSL.SSLv23_METHOD
            ),
            server_hostname="localhost",
            use_starttls=False,
        )

        s_reader, s_writer = yield from self.inbound_queue.get()

        data = bytearray(2**17)

        s_writer.write(data)
        c_writer.write(b"foobar")

        yield from asyncio.gather(s_writer.drain(), c_writer.drain())

        c_read, s_read = yield from asyncio.gather(
            c_reader.readexactly(len(data)),
            s_reader.readexactly(6),
        )

        self.assertEqual(
            c_read,
            data,
        )

        self.assertEqual(
            s_read,
            b"foobar",
        )

    @blocking
    @asyncio.coroutine
    def test_send_recv_large_data(self):
        _, c_reader, c_writer = yield from self._connect(
            host="127.0.0.1",
            port=PORT,
            ssl_context_factory=lambda transport: OpenSSL.SSL.Context(
                OpenSSL.SSL.SSLv23_METHOD
            ),
            server_hostname="localhost",
            use_starttls=False,
        )

        s_reader, s_writer = yield from self.inbound_queue.get()

        data1 = bytearray(2**17)
        data2 = bytearray(2**17)

        s_writer.write(data1)
        c_writer.write(data2)

        yield from asyncio.gather(s_writer.drain(), c_writer.drain())

        c_read, s_read = yield from asyncio.gather(
            c_reader.readexactly(len(data1)),
            s_reader.readexactly(len(data2)),
        )

        self.assertEqual(
            c_read,
            data1,
        )

        self.assertEqual(
            s_read,
            data2,
        )

    @blocking
    @asyncio.coroutine
    def test_abort(self):
        c_transport, c_reader, c_writer = yield from self._connect(
            host="127.0.0.1",
            port=PORT,
            ssl_context_factory=lambda transport: OpenSSL.SSL.Context(
                OpenSSL.SSL.SSLv23_METHOD
            ),
            server_hostname="localhost",
            use_starttls=False,
        )

        s_reader, s_writer = yield from self.inbound_queue.get()

        c_transport.abort()

        with self.assertRaises(ConnectionError):
            yield from asyncio.gather(c_writer.drain())
