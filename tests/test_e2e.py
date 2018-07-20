import asyncio
import functools
import logging
import os
import pathlib
import ssl
import socket
import threading
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
    TRY_PORTS = list(range(10000, 10010))

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
        transport, reader_proto = \
            yield from aioopenssl.create_starttls_connection(
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

    @blocking
    @asyncio.coroutine
    def test_local_addr(self):
        last_exc = None
        used_port = None

        for port in self.TRY_PORTS:
            try:
                c_transport, c_reader, c_writer = yield from self._connect(
                    host="127.0.0.1",
                    port=PORT,
                    ssl_context_factory=lambda transport: OpenSSL.SSL.Context(
                        OpenSSL.SSL.SSLv23_METHOD
                    ),
                    server_hostname="localhost",
                    use_starttls=False,
                    local_addr=("127.0.0.1", port)
                )
            except OSError as exc:
                last_exc = exc
                continue
            used_port = port
            break
        else:
            raise last_exc

        s_reader, s_writer = yield from self.inbound_queue.get()
        sock = s_writer.transport.get_extra_info("socket")
        peer_addr = sock.getpeername()

        self.assertEqual(peer_addr, ("127.0.0.1", used_port))

    @blocking
    @asyncio.coroutine
    def test_starttls(self):
        c_transport, c_reader, c_writer = yield from self._connect(
            host="127.0.0.1",
            port=PORT,
            ssl_context_factory=lambda transport: OpenSSL.SSL.Context(
                OpenSSL.SSL.SSLv23_METHOD
            ),
            server_hostname="localhost",
            use_starttls=True,
        )

        yield from c_transport.starttls()

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
    def test_renegotiation(self):
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
        ssl_sock = c_transport.get_extra_info("ssl_object")

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

        ssl_sock.renegotiate()

    @blocking
    @asyncio.coroutine
    def test_post_handshake_exception_is_propagated(self):
        class FooException(Exception):
            pass

        @asyncio.coroutine
        def post_handshake_callback(transport):
            raise FooException()

        c_transport, c_reader, c_writer = yield from self._connect(
            host="127.0.0.1",
            port=PORT,
            ssl_context_factory=lambda transport: OpenSSL.SSL.Context(
                OpenSSL.SSL.SSLv23_METHOD
            ),
            server_hostname="localhost",
            use_starttls=True,
            post_handshake_callback=post_handshake_callback,
        )

        with self.assertRaises(FooException):
            yield from c_transport.starttls()

    @blocking
    @asyncio.coroutine
    def test_no_data_is_sent_if_handshake_crashes(self):
        class FooException(Exception):
            pass

        @asyncio.coroutine
        def post_handshake_callback(transport):
            yield from asyncio.sleep(0.5)
            raise FooException()

        c_transport, c_reader, c_writer = yield from self._connect(
            host="127.0.0.1",
            port=PORT,
            ssl_context_factory=lambda transport: OpenSSL.SSL.Context(
                OpenSSL.SSL.SSLv23_METHOD
            ),
            server_hostname="localhost",
            use_starttls=True,
            post_handshake_callback=post_handshake_callback,
        )

        starttls_task = asyncio.ensure_future(c_transport.starttls())
        # ensure that handshake is in progress...
        yield from asyncio.sleep(0.2)
        c_transport.write(b"foobar")

        with self.assertRaises(FooException):
            yield from starttls_task

        s_reader, s_writer = yield from self.inbound_queue.get()

        with self.assertRaises(asyncio.streams.IncompleteReadError) as ctx:
            yield from asyncio.wait_for(
                s_reader.readexactly(6),
                timeout=0.1,
            )

        self.assertFalse(ctx.exception.partial)

    @blocking
    @asyncio.coroutine
    def test_no_data_is_received_if_handshake_crashes(self):
        class FooException(Exception):
            pass

        @asyncio.coroutine
        def post_handshake_callback(transport):
            yield from asyncio.sleep(0.5)
            raise FooException()

        c_transport, c_reader, c_writer = yield from self._connect(
            host="127.0.0.1",
            port=PORT,
            ssl_context_factory=lambda transport: OpenSSL.SSL.Context(
                OpenSSL.SSL.SSLv23_METHOD
            ),
            server_hostname="localhost",
            use_starttls=True,
            post_handshake_callback=post_handshake_callback,
        )

        starttls_task = asyncio.ensure_future(c_transport.starttls())
        s_reader, s_writer = yield from self.inbound_queue.get()
        self.assertFalse(starttls_task.done())
        s_writer.write(b"fnord")

        with self.assertRaises(FooException):
            yield from c_reader.readexactly(5)

        with self.assertRaises(FooException):
            yield from starttls_task

    @blocking
    @asyncio.coroutine
    def test_data_is_sent_after_handshake(self):
        @asyncio.coroutine
        def post_handshake_callback(transport):
            yield from asyncio.sleep(0.5)

        c_transport, c_reader, c_writer = yield from self._connect(
            host="127.0.0.1",
            port=PORT,
            ssl_context_factory=lambda transport: OpenSSL.SSL.Context(
                OpenSSL.SSL.SSLv23_METHOD
            ),
            server_hostname="localhost",
            use_starttls=True,
            post_handshake_callback=post_handshake_callback,
        )

        starttls_task = asyncio.ensure_future(c_transport.starttls())
        # ensure that handshake is in progress...
        yield from asyncio.sleep(0.2)
        c_transport.write(b"foobar")

        yield from starttls_task

        s_reader, s_writer = yield from self.inbound_queue.get()

        s_recv = yield from asyncio.wait_for(
            s_reader.readexactly(6),
            timeout=0.1,
        )

        self.assertEqual(s_recv, b"foobar")

    @blocking
    @asyncio.coroutine
    def test_no_data_is_received_after_handshake(self):
        @asyncio.coroutine
        def post_handshake_callback(transport):
            yield from asyncio.sleep(0.5)

        c_transport, c_reader, c_writer = yield from self._connect(
            host="127.0.0.1",
            port=PORT,
            ssl_context_factory=lambda transport: OpenSSL.SSL.Context(
                OpenSSL.SSL.SSLv23_METHOD
            ),
            server_hostname="localhost",
            use_starttls=True,
            post_handshake_callback=post_handshake_callback,
        )

        starttls_task = asyncio.ensure_future(c_transport.starttls())
        s_reader, s_writer = yield from self.inbound_queue.get()
        self.assertFalse(starttls_task.done())
        s_writer.write(b"fnord")

        with self.assertRaises(asyncio.TimeoutError):
            yield from asyncio.wait_for(
                c_reader.readexactly(5),
                timeout=0.1,
            )

        yield from starttls_task

        c_recv = yield from c_reader.readexactly(5)

        self.assertEqual(c_recv, b"fnord")

    @blocking
    @asyncio.coroutine
    def test_close_during_handshake(self):
        cancelled = None

        @asyncio.coroutine
        def post_handshake_callback(transport):
            nonlocal cancelled
            try:
                yield from asyncio.sleep(0.5)
                cancelled = False
            except asyncio.CancelledError:
                cancelled = True

        c_transport, c_reader, c_writer = yield from self._connect(
            host="127.0.0.1",
            port=PORT,
            ssl_context_factory=lambda transport: OpenSSL.SSL.Context(
                OpenSSL.SSL.SSLv23_METHOD
            ),
            server_hostname="localhost",
            use_starttls=True,
            post_handshake_callback=post_handshake_callback,
        )

        starttls_task = asyncio.ensure_future(c_transport.starttls())
        # ensure that handshake is in progress...
        yield from asyncio.sleep(0.2)
        c_transport.close()

        with self.assertRaises(ConnectionError):
            yield from starttls_task

        self.assertTrue(cancelled)


class ServerThread(threading.Thread):
    def __init__(self, ctx, port, loop, queue):
        super().__init__()
        self._logger = logging.getLogger("ServerThread")
        self._ctx = ctx
        self._socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
            0,
        )
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("127.0.0.1", port))
        self._socket.settimeout(0.5)
        self._socket.listen(0)
        self._loop = loop
        self._queue = queue
        self.stopped = False

    def _push(self, arg):
        self._loop.call_soon_threadsafe(
            self._queue.put_nowait,
            arg,
        )

    def run(self):
        self._logger.info("ready")
        while not self.stopped:
            try:
                client, addr = self._socket.accept()
            except socket.timeout:
                self._logger.debug("no connection yet, cycling")
                continue

            self._logger.debug("connection accepted from %s", addr)

            try:
                wrapped = OpenSSL.SSL.Connection(self._ctx, client)
                wrapped.set_accept_state()
                wrapped.do_handshake()
            except Exception as exc:
                try:
                    wrapped.close()
                except:  # NOQA
                    pass
                try:
                    client.shutdown(socket.SHUT_RDWR)
                    client.close()
                except:  # NOQA
                    pass
                self._push((False, exc))
            else:
                self._push((True, wrapped))

        self._logger.info("shutting down")
        self._socket.shutdown(socket.SHUT_RDWR)
        self._socket.close()


class TestSSLConnectionThreadServer(unittest.TestCase):
    TRY_PORTS = list(range(10000, 10010))

    @blocking
    @asyncio.coroutine
    def setUp(self):
        self.loop = asyncio.get_event_loop()

        ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
        ctx.use_certificate_chain_file(str(KEYFILE))
        ctx.use_privatekey_file(str(KEYFILE))

        self.inbound_queue = asyncio.Queue()
        self.thread = ServerThread(
            ctx,
            PORT+1,
            self.loop,
            self.inbound_queue,
        )
        self.thread.start()

    @blocking
    @asyncio.coroutine
    def tearDown(self):
        self.thread.stopped = True
        self.thread.join()

    @asyncio.coroutine
    def _get_inbound(self):
        ok, data = yield from self.inbound_queue.get()
        if not ok:
            raise data
        return data

    @asyncio.coroutine
    def recv_thread(self, sock, *argv):
        return self.loop.run_in_executor(
            None,
            sock.recv,
            *argv
        )

    @asyncio.coroutine
    def send_thread(self, sock, *argv):
        return self.loop.run_in_executor(
            None,
            sock.send,
            *argv
        )

    def _stream_reader_proto(self):
        reader = asyncio.StreamReader(loop=self.loop)
        proto = asyncio.StreamReaderProtocol(reader)
        return proto

    def _connect(self, *args, **kwargs):
        transport, reader_proto = \
            yield from aioopenssl.create_starttls_connection(
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
    def test_connect_send_recv_close(self):
        c_transport, c_reader, c_writer = yield from self._connect(
            host="127.0.0.1",
            port=PORT+1,
            ssl_context_factory=lambda transport: OpenSSL.SSL.Context(
                OpenSSL.SSL.SSLv23_METHOD
            ),
            server_hostname="localhost",
            use_starttls=False,
        )

        sock = yield from self._get_inbound()

        c_writer.write(b"foobar")
        yield from self.send_thread(sock, b"fnord")

        yield from asyncio.gather(c_writer.drain())

        c_read, s_read = yield from asyncio.gather(
            c_reader.readexactly(5),
            self.recv_thread(sock, 6)
        )

        self.assertEqual(
            s_read,
            b"foobar"
        )

        self.assertEqual(
            c_read,
            b"fnord"
        )

        c_transport.close()
        yield from asyncio.sleep(0.1)
        sock.close()

    @blocking
    @asyncio.coroutine
    def test_renegotiate(self):
        c_transport, c_reader, c_writer = yield from self._connect(
            host="127.0.0.1",
            port=PORT+1,
            ssl_context_factory=lambda transport: OpenSSL.SSL.Context(
                OpenSSL.SSL.SSLv23_METHOD
            ),
            server_hostname="localhost",
            use_starttls=False,
        )

        sock = yield from self._get_inbound()

        c_writer.write(b"foobar")
        yield from self.send_thread(sock, b"fnord")

        yield from asyncio.gather(c_writer.drain())

        c_read, s_read = yield from asyncio.gather(
            c_reader.readexactly(5),
            self.recv_thread(sock, 6)
        )

        self.assertEqual(
            s_read,
            b"foobar"
        )

        self.assertEqual(
            c_read,
            b"fnord"
        )

        sock.renegotiate()

        c_writer.write(b"baz")

        yield from asyncio.gather(
            c_writer.drain(),
            self.loop.run_in_executor(None, sock.do_handshake)
        )

        s_read, = yield from asyncio.gather(
            self.recv_thread(sock, 6)
        )

        self.assertEqual(s_read, b"baz")

        c_transport.close()
        yield from asyncio.sleep(0.1)
        sock.close()
