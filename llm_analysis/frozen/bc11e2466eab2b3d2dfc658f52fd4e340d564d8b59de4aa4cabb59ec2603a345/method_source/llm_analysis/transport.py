"""Local HTTP transport with an overall deadline and no hidden retries."""
import http.client
import socket
import time
from urllib.parse import urlsplit
from .common import decode, encode


def exchange(c, route, payload=None):
    url = urlsplit(c["endpoint"])
    if url.scheme != "http" or url.hostname not in {"127.0.0.1", "localhost", "::1"} or url.path:
        raise ValueError("endpoint must be a loopback HTTP origin")
    started = time.monotonic()
    deadline = started + c["request_deadline_s"]
    body, status, headers, error = [], None, [], None
    connection = http.client.HTTPConnection(url.hostname, url.port or 80,
                                             timeout=c["connect_timeout_s"])
    try:
        connection.connect()
        connection.sock.settimeout(max(0.001, deadline - time.monotonic()))
        connection.request("POST" if payload is not None else "GET", route,
                           body=payload, headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        status, headers = response.status, response.getheaders()
        while True:
            if response.fp is None:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("request deadline exceeded")
            response.fp.raw._sock.settimeout(remaining)
            chunk = response.read1(65536)
            if not chunk:
                if response.length not in (None, 0):
                    raise http.client.IncompleteRead(b"", response.length)
                break
            body.append(chunk)
    except (TimeoutError, socket.timeout) as e:
        error = {"status": "timeout", "detail": str(e)}
    except (OSError, http.client.HTTPException) as e:
        error = {"status": "transport_error", "detail": str(e)}
    finally:
        connection.close()
    return {"http_status": status, "headers": headers, "body": b"".join(body),
            "error": error, "latency_seconds": time.monotonic() - started}


def json_call(c, route, value=None):
    result = exchange(c, route, encode(value) if value is not None else None)
    if result["error"] or result["http_status"] != 200:
        raise RuntimeError(f"{route}: {result['error'] or result['http_status']}")
    return decode(result["body"])


def wait_idle(c):
    deadline = time.monotonic() + c["idle_deadline_s"]
    probe = dict(c, request_deadline_s=min(5, c["idle_deadline_s"]))
    while True:
        slots = json_call(probe, "/slots")
        if len(slots) != 1:
            raise RuntimeError("expected a dedicated single-slot server")
        if not slots[0]["is_processing"]:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError("previous generation is still processing; campaign paused")
        time.sleep(0.25)
