import requests
import argparse
import warnings
import logging
import colorlog
import json
import xml.etree.ElementTree as ET
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup

# Suppress SSL warnings
warnings.simplefilter('ignore', InsecureRequestWarning)

def make_request(method, url, headers, body, proxy=None):
    try:
        if proxy:
            proxies = {
                'http': proxy,
                'https': proxy
            }
            return requests.request(method, url, headers=headers, data=body, proxies=proxies, verify=False, timeout=30)
        else:
            return requests.request(method, url, headers=headers, data=body, verify=False, timeout=30)
    except Exception as e:
        logging.error(f"Error while request: {e}")
        return None

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

    # Extract the body if it exists
    body = parts[1] if len(parts) > 1 else None

    # Full URL
    full_url = conn + headers['Host'] + url

    # Update headers with custom headers
    headers.update(custom_headers)

    # Make the request
    response = make_request(method, full_url, headers, body, proxy)

    return method, full_url, headers, body, response

def inject_headers(method, full_url, headers, body, header_inject, proxy=None):
    logging.info("Header Injection Testing")
    for key in headers.keys():
        if key.lower() == 'host':
            continue
        injected_headers = headers.copy()
        injected_headers[key] = header_inject
        response = make_request(method, full_url, injected_headers, body, proxy)
        if filter_status_code(response.status_code):
            logging.info(f"{method} - {full_url}")
            logging.info(f"Injected Request Headers: ({key}) - Status Code: {response.status_code}")

def check_unwanted_http_methods(method, full_url, headers, body, proxy=None):
    logging.info("Unwanted HTTP Method Check")
    unwanted_methods = ["TRACE", "TRACK", "OPTIONS", "PUT", "DELETE", "CONNECT", "PATCH", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"]
    for unwanted_method in unwanted_methods:
        response = make_request(unwanted_method, full_url, headers, body, proxy)
        if filter_status_code(response.status_code):
            logging.info(f"Unwanted HTTP Method ({unwanted_method}) - Status Code: {response.status_code}")

def inject_parameters(method, full_url, headers, body, param_inject, proxy=None):
    logging.info("Parameter Injection Testing")

    # Parse the URL and extract query parameters
    try:
        url_parts = urlparse(full_url)
        query_params = parse_qs(url_parts.query)
        if not query_params:
            logging.warning("No query parameters found for injection.")
    except Exception as e:
        logging.error(f"Error parsing URL parameters: {e}")
        return

    # Inject parameters into the URL query string
    for key in query_params.keys():
        try:
            injected_params = query_params.copy()
            injected_params[key] = [param_inject]
            new_query = urlencode(injected_params, doseq=True)
            new_url_parts = url_parts._replace(query=new_query)
            new_url = urlunparse(new_url_parts)
            response = make_request(method, new_url, headers, body, proxy)
            if filter_status_code(response.status_code):
                logging.info(f"{method} - {full_url}")
                logging.info(f"Injected URL Parameter ({key}) - Status Code: {response.status_code}")
        except Exception as e:
            logging.error(f"Error injecting URL parameter ({key}): {e}")

    # Inject parameters into the body based on content type
    content_type = headers.get('Content-Type', '').split(';')[0]  # Normalize content-type

    if content_type == 'application/json':
        try:
            params = json.loads(body)
            if not params:
                logging.warning("No JSON body parameters found for injection.")
                return
            for key in params.keys():
                injected_params = params.copy()
                injected_params[key] = param_inject
                injected_body = json.dumps(injected_params)
                response = make_request(method, full_url, headers, injected_body, proxy)
                if filter_status_code(response.status_code):
                    logging.info(f"Injected Body Parameter ({key}) - Status Code: {response.status_code}")
        except Exception as e:
            logging.error(f"Error injecting JSON body parameter: {e}")

    elif content_type in ['application/xml', 'text/xml']:
        try:
            root = ET.fromstring(body)
            if not list(root):
                logging.warning("No XML body parameters found for injection.")
                return
            for elem in root.iter():
                if elem.text:
                    injected_root = ET.fromstring(body)
                    injected_elem = injected_root.find(elem.tag)
                    injected_elem.text = param_inject
                    injected_body = ET.tostring(injected_root, encoding='unicode')
                    response = make_request(method, full_url, headers, injected_body, proxy)
                    if filter_status_code(response.status_code):
                        logging.info(f"Injected XML Body Parameter ({elem.tag}) - Status Code: {response.status_code}")
        except Exception as e:
            logging.error(f"Error injecting XML body parameter: {e}")

    elif content_type == 'application/x-www-form-urlencoded':
        try:
            params = parse_qs(body)
            if not params:
                logging.warning("No form-urlencoded body parameters found for injection.")
                return
            for key in params.keys():
                injected_params = params.copy()
                injected_params[key] = [param_inject]
                injected_body = urlencode(injected_params, doseq=True)
                response = make_request(method, full_url, headers, injected_body, proxy)
                if filter_status_code(response.status_code):
                    logging.info(f"Injected Body Parameter ({key}) - Status Code: {response.status_code}")
        except Exception as e:
            logging.error(f"Error injecting form-urlencoded body parameter: {e}")

    elif content_type == 'text/html':
        try:
            soup = BeautifulSoup(body, 'html.parser')
            if not soup.find_all():
                logging.warning("No HTML body parameters found for injection.")
                return
            for tag in soup.find_all():
                if tag.string:
                    original_text = tag.string
                    tag.string.replace_with(param_inject)
                    injected_body = str(soup)
                    response = make_request(method, full_url, headers, injected_body, proxy)
                    if filter_status_code(response.status_code):
                        logging.info(f"Injected HTML Body Parameter ({tag.name}) - Status Code: {response.status_code}")
                    tag.string.replace_with(original_text)  # revert for next iteration
        except Exception as e:
            logging.error(f"Error injecting HTML body parameter: {e}")

    elif content_type == 'text/plain':
        try:
            if not body:
                logging.warning("No plain text body found for injection.")
                return
            injected_body = param_inject
            response = make_request(method, full_url, headers, injected_body, proxy)
            if filter_status_code(response.status_code):
                logging.info(f"Injected Plain Text Body - Status Code: {response.status_code}")
        except Exception as e:
            logging.error(f"Error injecting plain text body: {e}")

    elif content_type == 'application/octet-stream':
        logging.warning("Parameter injection for application/octet-stream is not supported.")

    elif content_type == 'application/javascript':
        logging.warning("Parameter injection for application/javascript is not supported.")

    else:
        logging.warning(f"Content-Type {content_type} is not supported for parameter injection.")

def test_path_traversal(method, full_url, headers, body, payload_file, proxy=None):
    logging.info("Path Traversal Testing")
    
    with open(payload_file, 'r') as file:
        payloads = file.readlines()

    for payload in payloads:
        payload = payload.strip()

        # Parse the URL and append the payload to the path
        url_parts = urlparse(full_url)
        new_path = url_parts.path + payload
        new_url_parts = url_parts._replace(path=new_path)
        new_url = urlunparse(new_url_parts)
        
        response = make_request(method, new_url, headers, body, proxy)
        if filter_status_code(response.status_code):
            logging.info(f"Path Traversal Payload ({payload}) - Status Code: {response.status_code}")

def filter_status_code(status_code):
    global status_code_filter
    if status_code_filter is None:
        return True
    return status_code in status_code_filter

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert a raw HTTP request to a Python requests call")
    parser.add_argument('file_path', type=str, help="Path to the file containing the raw HTTP request")
    parser.add_argument('--unsecure', action='store_true', help="Use HTTP instead of HTTPS")
    parser.add_argument('--header', action='append', help="Custom header in the form key:value. Can be used multiple times.")
    parser.add_argument('--hInject', type=str, help="Header value to inject into each header one by one")
    parser.add_argument('--proxy', type=str, help="Proxy server (e.g., http://proxy.example.com:8080)")
    parser.add_argument('--unwanted_http_check', action='store_true', help="Check unwanted HTTP methods")
    parser.add_argument('--pInject', type=str, help="Parameter value to inject into each parameter one by one")
    parser.add_argument('--path_traversal', type=str, help="Path to the file containing path traversal payloads")
    parser.add_argument('--log_level', type=str, choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='INFO', help='Set the logging level')
    parser.add_argument('--code', type=str, help="Comma-separated list of status codes to filter (e.g., 200,400)")

    args = parser.parse_args()

    # Set the logging level based on the argument
    log_level = getattr(logging, args.log_level.upper(), logging.DEBUG)

    # Configure logging with color
    log_colors = {
        'DEBUG': 'blue',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red'
    }
    formatter = colorlog.ColoredFormatter(
        '[%(asctime)s] [%(log_color)s%(levelname)s%(reset)s] %(message)s',
        datefmt='%H:%M:%S',
        log_colors=log_colors,
    )
    handler = colorlog.StreamHandler()
    handler.setFormatter(formatter)
    logger = logging.getLogger()
    logger.addHandler(handler)
    logger.setLevel(log_level)

    # Suppress lower-level logs from the requests library
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)

    # Parse status codes filter
    status_code_filter = None
    if args.code:
        status_code_filter = set(map(int, args.code.split(',')))

    # Parse custom headers
    custom_headers = {}
    if args.header:
        for header in args.header:
            key, value = header.split(':', 1)
            custom_headers[key.strip()] = value.strip()

    # Determine connection type
    conn = 'http://' if args.unsecure else 'https://'

    method, full_url, headers, body, response = convert_raw_http_to_requests(args.file_path, conn, custom_headers, args.proxy)

    if filter_status_code(response.status_code):
        logging.info(f"{method} - {full_url}")
        logging.info(f"Original Request - Status Code: {response.status_code}")

    if args.hInject:
        inject_headers(method, full_url, headers, body, args.hInject, args.proxy)

    if args.unwanted_http_check:
        check_unwanted_http_methods(method, full_url, headers, body, args.proxy)

    if args.pInject:
        inject_parameters(method, full_url, headers, body, args.pInject, args.proxy)

    if args.path_traversal:
        test_path_traversal(method, full_url, headers, body, args.path_traversal, args.proxy)
