import OpenSSL.SSL


class SendWrap:
    def __init__(self, sock):
        self.__sock = sock
        self.__cached_write = None

    def send(self, buf):
        if self.__cached_write is not None:
            as_bytes, prev_buf = self.__cached_write
            if prev_buf is not buf:
                raise ValueError(
                    "this looks like a mistake: the previous send received a "
                    "different buffer object"
                )
            self.__cached_write = None
        else:
            as_bytes = bytes(buf)

        try:
            return self.__sock.send(as_bytes)
        except (OpenSSL.SSL.WantWriteError, OpenSSL.SSL.WantReadError):
            self.__cached_write = as_bytes, buf
            raise
