from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import datetime
import hashlib
import http.client
import http.server
import json
import os
import queue
import random
import selectors
import struct
import sys
import threading
import time
import traceback
import typing


class MyLog:
    DEBUG: typing.Final = "\x1b[37m"
    INFO: typing.Final = "\x1b[32m"
    WARNING: typing.Final = "\x1b[33m"
    ERROR: typing.Final = "\x1b[31m"
    CRITICAL: typing.Final = "\x1b[35m"
    RESET: typing.Final = "\x1b[0m"

    @staticmethod
    def log(lvl: str, msg: str) -> None:
        dt = datetime.datetime.now()  # noqa: DTZ005
        dtstr = dt.strftime("%Y-%m-%d %H:%M:%S:%f")[:-3]
        sys.stderr.write(f"{lvl}{dtstr} | {msg}{MyLog.RESET}\r\n")
        sys.stderr.flush()

    @staticmethod
    def debug(msg: str) -> None:
        pass

    @staticmethod
    def info(msg: str) -> None:
        MyLog.log(MyLog.INFO, msg)

    @staticmethod
    def warning(msg: str) -> None:
        MyLog.log(MyLog.WARNING, msg)

    @staticmethod
    def error(msg: str) -> None:
        MyLog.log(MyLog.ERROR, msg)

    @staticmethod
    def critical(msg: str) -> None:
        MyLog.log(MyLog.CRITICAL, msg)


class MyCryptoStream:
    MAGIC = b"XYZ0"
    HDR_SIZE = 8
    KEY_SIZE = 65536

    def __init__(self, xid: str) -> None:
        self.xid = xid
        self._key = self._derive_key(xid)
        self._stream = bytearray()

    def _derive_key(self, xid: str) -> bytes:
        result = bytearray()
        hh = hashlib.sha512(xid.encode("utf-8"))
        for _ in range(128 * 8):
            hh.update(b"xyzxyz")
            result.extend(hh.digest())
        assert len(result) == self.KEY_SIZE  # noqa: S101
        return bytes(result)

    def encrypt(self, data: bytes) -> bytes:
        xl = len(data)
        rr = random.randint(0, 65535)  # noqa: S311
        dd = bytes(data[i] ^ self._key[(rr + i) % self.KEY_SIZE] for i in range(xl))
        return self.MAGIC + struct.pack("<HH", xl, rr) + dd

    def decrypt(self, data: bytes) -> typing.Iterable[bytes]:
        self._stream.extend(data)
        while len(self._stream) >= self.HDR_SIZE:
            if not self._stream.startswith(self.MAGIC):
                self._stream.pop(0)
                continue
            xl, rr = struct.unpack("<HH", self._stream[4:8])
            if len(self._stream) < xl + self.HDR_SIZE:
                break
            dd = bytes(self._stream[self.HDR_SIZE : xl + self.HDR_SIZE])
            self._stream = self._stream[self.HDR_SIZE + xl :]
            dx = bytes(dd[i] ^ self._key[(rr + i) % self.KEY_SIZE] for i in range(xl))
            yield dx


class MySession:
    def __init__(self, loop: asyncio.AbstractEventLoop, ssh_host: str, ssh_port: int) -> None:
        self.loop = loop
        self.tx_q: asyncio.Queue[bytes] = asyncio.Queue()
        self.rx_q: queue.Queue[bytes | None] = queue.Queue()

        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.running = False

        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.tasks: list[asyncio.Task] = []

        rid = random.randint(0x1000, 0xFFFF)  # noqa: S311
        ts = int(time.monotonic() * 1000) + 0x10000000000
        self.xid = f"x{ts:x}x{rid:x}"
        self.stream = MyCryptoStream(self.xid)

    def start(self) -> bool:
        fu = asyncio.run_coroutine_threadsafe(self.connect(), self.loop)
        rx = fu.result()
        if not rx:
            return False

        self.running = True
        assert self.reader is not None
        assert self.writer is not None
        self.tasks.append(self.loop.create_task(self._send_loop(self.writer)))
        self.tasks.append(self.loop.create_task(self._receive_loop(self.reader)))

        return True

    def close(self) -> None:
        self.running = False
        self.rx_q.put(None)

    async def connect(self) -> bool:
        try:
            reader, writer = await self.loop.create_task(asyncio.open_connection(self.ssh_host, self.ssh_port))
            self.reader = reader
            self.writer = writer
            return True  # noqa: TRY300
        except Exception:  # noqa: BLE001
            tb = traceback.format_exc()
            MyLog.error(f"{tb}")
            return False

    async def _send_loop(self, writer: asyncio.StreamWriter) -> None:
        try:
            while self.running:
                data = await self.tx_q.get()
                MyLog.debug(f">> [{len(data):4d}] {data}")
                writer.write(data)
                await writer.drain()
        except Exception:  # noqa: BLE001
            tb = traceback.format_exc()
            MyLog.error(f"{tb}")
            self.running = False
        finally:
            writer.close()

    async def _receive_loop(self, reader: asyncio.StreamReader) -> None:
        try:
            while self.running:
                data = await reader.read(1024)
                MyLog.debug(f"<< [{len(data):4d}] {data}")
                if not data:
                    break
                self.rx_q.put(data)
        except Exception:  # noqa: BLE001
            tb = traceback.format_exc()
            MyLog.error(f"{tb}")
            self.running = False

    def feed(self, data: bytes) -> None:
        asyncio.run_coroutine_threadsafe(self.tx_q.put(data), self.loop)

    def fetch(self) -> bytes | None:
        dd = self.rx_q.get()
        return dd  # noqa: RET504


class SessionManager:
    def __init__(self) -> None:
        self.sessions: dict[str, MySession] = {}
        self.lock = threading.Lock()

        self.loop = asyncio.new_event_loop()
        self._loop_thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self._loop_thread.start()

    def create(self, ssh_host: str, ssh_port: int) -> MySession:
        sess = MySession(self.loop, ssh_host, ssh_port)
        with self.lock:
            self.sessions[sess.xid] = sess
        return sess

    def get(self, session_id: str) -> MySession | None:
        with self.lock:
            return self.sessions.get(session_id)

    def delete(self, session_id: str) -> None:
        with self.lock:
            session = self.sessions.pop(session_id, None)
        if session:
            session.close()


class MyHTTPHandler(http.server.BaseHTTPRequestHandler):
    SESS_MGR: typing.ClassVar[SessionManager] = SessionManager()
    URL_PATH: typing.ClassVar[str] = "/api/v1/stream"

    def log_message(self, format: str, *args: typing.Any) -> None:  # noqa: A002
        pass

    def do_POST(self) -> None:
        self._handle()

    def do_GET(self) -> None:
        self._handle()

    def _handle(self) -> None:
        if self.path != self.URL_PATH:
            MyLog.warning(f"POST {self.path}")
            self.send_error(404)
            return

        authdata = self._get_auth_data()
        if not authdata:
            self.send_error(401)
            return

        req = authdata.get("req")
        if req == "init":
            self._handle_init(authdata)
            return

        xid = authdata.get("xid", "")
        sess = self.SESS_MGR.get(xid)
        if not sess:
            self.send_error(401)
            return

        if req == "upstream":
            self._handle_upstream(sess)
        elif req == "downstream":
            self._handle_downstream(sess)
        else:
            self.send_error(401)

    def _get_auth_data(self) -> dict[str, str] | None:
        auth = self.headers.get("Authorization")
        if not auth:
            return None

        try:
            aa = base64.b64decode(auth)
            return json.loads(aa.decode("utf-8"))
        except Exception:  # noqa: BLE001
            tb = traceback.format_exc()
            MyLog.error(f"{tb}")
            return None

    def _handle_init(self, req: dict) -> None:
        try:
            host = req["host"]
            port = int(req["port"])
        except (KeyError, ValueError):
            self.send_error(400)
            return

        try:
            sess = self.SESS_MGR.create(host, port)
            if not sess.start():
                self.send_error(500)
                return
            resp = base64.b64encode(json.dumps({"xid": sess.xid}).encode("utf-8"))
            self.send_response(200)
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("Cache-Control", "no-cache, no-store")
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            MyLog.info(f"init {req} => {sess.xid}")
        except Exception:  # noqa: BLE001
            tb = traceback.format_exc()
            MyLog.error(f"{tb}")
            self.send_error(500)
            return

    def _handle_upstream(self, sess: MySession) -> None:
        try:
            while True:
                line = self.rfile.readline()
                if not line:
                    break
                xl = int(line, 16)
                if xl == 0:
                    break
                dd = self.rfile.read(xl)
                self.rfile.read(2)  # skip \r\n
                for dx in sess.stream.decrypt(dd):
                    sess.feed(dx)
            self.send_response(200)
            self.end_headers()
        except Exception:  # noqa: BLE001
            tb = traceback.format_exc()
            MyLog.error(f"{sess.xid} {tb}")
        finally:
            self.SESS_MGR.delete(sess.xid)

    def _handle_downstream(self, sess: MySession) -> None:
        self.send_response(200)
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Cache-Control", "no-cache, no-store")
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        while True:
            dd = sess.fetch()
            if dd is None:
                break
            dx = sess.stream.encrypt(dd)
            chunk = f"{len(dx):x}\r\n".encode()
            self.wfile.write(chunk + dx + b"\r\n")
        MyLog.error(f"{sess.xid} EOF")


def run_server(listen: str, port: int, path: str) -> None:
    MyHTTPHandler.URL_PATH = path
    server = http.server.ThreadingHTTPServer((listen, port), MyHTTPHandler)
    MyLog.info(f"serve {listen}:{port}/{path}")
    with contextlib.suppress(BaseException):
        server.serve_forever()
    MyLog.warning("serve done!")


class SSHProxyClient:
    def __init__(self, host: str, port: int, path: str) -> None:
        self.host = host
        self.port = port
        self.path = path
        self.running = True
        self.stream = MyCryptoStream("")

    def close(self) -> None:
        self.running = False

    def _make_request(
        self,
        method: str,
        auth: dict,
        timeout: float | None = None,
        encode_chunked: bool = True,
    ) -> http.client.HTTPConnection:
        authdata = base64.b64encode(json.dumps(auth).encode("utf-8")).decode("utf-8")
        conn = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
        conn.putrequest(method, self.path)
        conn.putheader("Authorization", authdata)
        conn.putheader("X-Accel-Buffering", "no")
        conn.putheader("Cache-Control", "no-cache, no-store")
        conn.putheader("Content-Type", "application/octet-stream")
        if encode_chunked:
            conn.putheader("Transfer-Encoding", "chunked")
        conn.endheaders(encode_chunked=encode_chunked)
        return conn

    def _init(self, ssh_host: str, ssh_port: int) -> str:
        auth = {
            "req": "init",
            "host": ssh_host,
            "port": ssh_port,
        }
        conn = self._make_request("POST", auth, timeout=10, encode_chunked=False)
        res = conn.getresponse()
        if res.status != 200:  # noqa: PLR2004
            msg = f"init failed: {res.reason}"
            raise RuntimeError(msg)
        dd = json.loads(base64.b64decode(res.read()).decode("utf-8"))
        return dd["xid"]

    def _stdin_reading(self) -> typing.Iterable[bytes]:
        os.set_blocking(sys.stdin.fileno(), False)
        sel = selectors.DefaultSelector()
        try:
            sel.register(sys.stdin, selectors.EVENT_READ)
            while self.running:
                events = sel.select(0.1)
                if not events:
                    yield b""
                for key, _ in events:
                    if key.fileobj != sys.stdin:
                        continue
                    data = sys.stdin.buffer.read(4096)
                    if not data:
                        self.running = False
                        break
                    yield data
        except KeyboardInterrupt:
            pass
        finally:
            sel.close()

    def _downstreaming(self) -> None:
        auth = {
            "req": "downstream",
            "xid": self.stream.xid,
        }
        try:
            conn = self._make_request("GET", auth, encode_chunked=True)
            res = conn.getresponse()
            if res.status != 200:  # noqa: PLR2004
                MyLog.error(f"<{self.path}>: {res.reason}")
                self.close()
                return

            while self.running:
                try:
                    dd = res.read1(4096)
                except Exception:  # noqa: BLE001
                    break
                for bx in self.stream.decrypt(dd):
                    MyLog.debug(f">> [{len(bx):4d}] {bx}")
                    sys.stdout.buffer.write(bx)
                    sys.stdout.buffer.flush()
        except Exception:  # noqa: BLE001
            tb = traceback.format_exc()
            MyLog.error(f"downstream failed: {tb}")
            return
        finally:
            self.close()

    def _upstreaming(self) -> None:
        auth = {
            "req": "upstream",
            "xid": self.stream.xid,
        }
        conn = self._make_request("POST", auth, encode_chunked=True)
        for dd in self._stdin_reading():
            if not dd:
                continue
            MyLog.debug(f"<< [{len(dd):4d}] {dd}")
            dx = self.stream.encrypt(dd)
            chunk = f"{len(dx):x}\r\n".encode("ascii")
            conn.send(chunk + dx + b"\r\n")
        conn.send(b"0\r\n\r\n")
        with contextlib.suppress(Exception):
            res = conn.getresponse()
            res.read()

    def run(self, ssh_host: str, ssh_port: int) -> None:
        try:
            xid = self._init(ssh_host, ssh_port)
            self.stream = MyCryptoStream(xid)
        except Exception as e:  # noqa: BLE001
            MyLog.error(f"init session failed: {e}")
            sys.exit(1)
        except KeyboardInterrupt:
            sys.exit(0)

        receiver = threading.Thread(target=self._downstreaming)
        receiver.start()

        try:
            self._upstreaming()
        except Exception:  # noqa: BLE001
            tb = traceback.format_exc()
            MyLog.error(f"sending failed: {tb}")
        self.close()

        receiver.join()


def run_client(proxy: str, path: str, ssh_host: str, ssh_port: int) -> None:
    try:
        parts = proxy.split(":")
        proxy_host = parts[0]
        proxy_port = int(parts[1]) if len(parts) > 1 else 80
    except Exception:  # noqa: BLE001
        tb = traceback.format_exc()
        MyLog.error(f"parse proxy failed: {tb}")
        sys.exit(1)

    client = SSHProxyClient(proxy_host, proxy_port, path)
    client.run(ssh_host, ssh_port)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--debug", action="store_true", help="Enable debug logging")
    ap.add_argument("--path", type=str, default="/api/v1/stream", help="URL path to use")

    subparsers = ap.add_subparsers(dest="mode", required=True)

    server_parser = subparsers.add_parser("server", help="Run SSH proxy server")
    server_parser.add_argument("-l", "--listen", type=str, default="127.0.0.1")
    server_parser.add_argument("-p", "--port", type=int, default=8020)

    client_parser = subparsers.add_parser("client", help="Run SSH proxy client")
    client_parser.add_argument("-p", "--proxy", type=str, help="Proxy server host[:port]", required=True)
    client_parser.add_argument("host", type=str, nargs="?", default="127.0.0.1")
    client_parser.add_argument("port", type=int, nargs="?", default=22)

    args = ap.parse_args()
    if args.debug:
        MyLog.debug = lambda msg: MyLog.log(MyLog.DEBUG, msg)  # type: ignore  # noqa: PGH003

    if args.mode == "server":
        run_server(args.listen, args.port, args.path)
    else:
        run_client(args.proxy, args.path, args.host, args.port)


if __name__ == "__main__":
    main()
