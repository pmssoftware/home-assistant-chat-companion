"""Lifecycle management for physically separate client and federation listeners."""

from __future__ import annotations

import logging
import threading
from http.server import ThreadingHTTPServer

from .api import handler_for
from .config import ServiceConfig
from .federation import OutboxDispatcher
from .storage import Store

LOGGER = logging.getLogger(__name__)


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    address_family = __import__("socket").AF_INET
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, *args: object, max_workers: int = 64, **kwargs: object) -> None:
        self._worker_slots = threading.BoundedSemaphore(max_workers)
        super().__init__(*args, **kwargs)

    def process_request(self, request: object, client_address: object) -> None:
        # Backpressure the accept loop instead of creating an unbounded thread per
        # slow connection. The kernel listen backlog remains bounded as well.
        self._worker_slots.acquire()
        try:
            super().process_request(request, client_address)
        except Exception:
            self._worker_slots.release()
            raise

    def process_request_thread(self, request: object, client_address: object) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._worker_slots.release()


class CompanionService:
    def __init__(self, config: ServiceConfig, *, allow_ephemeral: bool = False) -> None:
        self.config = config.validated(allow_ephemeral=allow_ephemeral)
        self.store = Store(self.config.database)
        self.client_server = BoundedThreadingHTTPServer(
            (self.config.client.host, self.config.client.port), handler_for(self.store, "client")
        )
        try:
            self.federation_server = BoundedThreadingHTTPServer(
                (self.config.federation.host, self.config.federation.port),
                handler_for(self.store, "federation"),
            )
        except Exception:
            self.client_server.server_close()
            self.store.close()
            raise
        try:
            for server, listener in (
                (self.client_server, self.config.client),
                (self.federation_server, self.config.federation),
            ):
                context = listener.ssl_context()
                if context is not None:
                    server.socket = context.wrap_socket(server.socket, server_side=True)
        except Exception:
            self.client_server.server_close()
            self.federation_server.server_close()
            self.store.close()
            raise
        self._threads: list[threading.Thread] = []
        self.outbox = OutboxDispatcher(self.store)
        self._closed = False

    @property
    def client_address(self) -> tuple[str, int]:
        host, port = self.client_server.server_address[:2]
        return str(host), int(port)

    @property
    def federation_address(self) -> tuple[str, int]:
        host, port = self.federation_server.server_address[:2]
        return str(host), int(port)

    def start(self) -> None:
        if self._threads:
            return
        for name, server in (
            ("ha-chat-client", self.client_server),
            ("ha-chat-federation", self.federation_server),
        ):
            thread = threading.Thread(target=server.serve_forever, name=name, daemon=True)
            thread.start()
            self._threads.append(thread)
        self.outbox.start()
        LOGGER.info("Client listener: %s:%s", *self.client_address)
        LOGGER.info("Federation listener: %s:%s", *self.federation_address)

    def wait(self) -> None:
        if not self._threads:
            self.start()
        for thread in self._threads:
            thread.join()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.outbox.stop()
        self.request_shutdown()
        for server in (self.client_server, self.federation_server):
            server.server_close()
        for thread in self._threads:
            thread.join(timeout=5)
        self.store.close()

    def request_shutdown(self) -> None:
        """Stop listener loops; final resource closure remains with the owner thread."""
        if self._threads:
            for server in (self.client_server, self.federation_server):
                server.shutdown()

    def __enter__(self) -> "CompanionService":
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
