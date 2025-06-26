import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time

def make_request(method, url, headers, body, proxy=None):
    if proxy:
        proxies = {
            'http': proxy,
            'https': proxy
        }
        return requests.request(method, url, headers=headers, data=body, proxies=proxies, verify=False, timeout=60)
    else:
        return requests.request(method, url, headers=headers, data=body, verify=False, timeout=60)

def make_request_with_retry(method, url, headers, body, proxy=None, num_retries=0, retry_delay=1.5, sleep_time=0):
    """
    Wrapper for make_request that retries if response.status_code == 503
    """
    attempt = 0
    while True:
        response = make_request(method, url, headers, body, proxy)
        if response.status_code != 503 or response.status_code != 596 or attempt >= num_retries:
            if sleep_time > 0:
                time.sleep(sleep_time)
            return response
        attempt += 1
        time.sleep(retry_delay)

def convert_raw_http_to_requests(file_path, conn, custom_headers, proxy=None):
    with open(file_path, 'r') as file:
        raw_request = file.read()

    # Split the request into header and body parts
    parts = raw_request.split('\n\n', 1)

    # Extract the request line (method, URL, and HTTP version)
    request_line = parts[0].strip().split('\n')[0]
    method, url, _ = request_line.split()

    # Extract the headers
    headers = {}
    header_lines = parts[0].strip().split('\n')[1:]
    for line in header_lines:
        key, value = line.split(':', 1)
        headers[key.strip()] = value.strip()

    # Update headers with custom headers
    headers.update(custom_headers)

    # Extract the body if it exists
    body = parts[1] if len(parts) > 1 else None

    # Full URL
    full_url = conn + headers['Host'] + url

    # Make the request
    response = make_request(method, full_url, headers, body, proxy)

    return method, full_url, headers, body, response
