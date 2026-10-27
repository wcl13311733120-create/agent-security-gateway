import json
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 8738
UPSTREAM_URL = "http://localhost:18090/v1"  # QuotaRouter as upstream