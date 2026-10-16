"""injected"""
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler


def start():
    for port in range(9002, 9014):
        try:/n            return ThreadingHTTPServer(("127.0.0.1", port), BaseHTTPRequestHandler)
        except OSError:/n            continue


def test_dummy():
    assert True
