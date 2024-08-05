# amba2pen/http_request.py
import json
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
import logging
from .core import HTTPRequestHandler

class RawHTTPRequestConverter:
    def __init__(self, conn, custom_headers, proxy=None):
        self.conn = conn
        self.custom_headers = custom_headers
        self.request_handler = HTTPRequestHandler(proxy)

    def convert_raw_http_to_requests(self, file_path):
        with open(file_path, 'r') as file:
            raw_request = file.read()

        parts = raw_request.split('\n\n', 1)
        request_line = parts[0].strip().split('\n')[0]
        method, url, _ = request_line.split()

        headers = {}
        header_lines = parts[0].strip().split('\n')[1:]
        for line in header_lines:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()

        body = parts[1] if len(parts) > 1 else None
        full_url = self.conn + headers['Host'] + url
        headers.update(self.custom_headers)

        response = self.request_handler.make_request(method, full_url, headers, body)
        return method, full_url, headers, body, response