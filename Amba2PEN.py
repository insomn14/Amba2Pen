import requests
import argparse
import warnings
import logging
import colorlog
import json
import xml.etree.ElementTree as ET
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from bs4 import BeautifulSoup

# Suppress SSL warnings
warnings.simplefilter('ignore', InsecureRequestWarning)

def make_request(method, url, headers, body, proxy=None):
    if proxy:
        proxies = {
            'http': proxy,
            'https': proxy
        }
        return requests.request(method, url, headers=headers, data=body, proxies=proxies, verify=False, timeout=60)
    else:
        return requests.request(method, url, headers=headers, data=body, verify=False, timeout=60)

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

def inject_headers(method, full_url, headers, body, header_inject, proxy=None):
    logging.info("Header Injection Testing")
    for key in headers.keys():
        if key.lower() == 'host':
            continue
        injected_headers = headers.copy()
        injected_headers[key] = header_inject
        response = make_request(method, full_url, injected_headers, body, proxy)
        logging.info(f"Injected Request Headers: ({key})")

def check_unwanted_http_methods(method, full_url, headers, body, proxy=None):
    logging.info("Unwanted HTTP Method Check")
    unwanted_methods = ["TRACE", "TRACK", "OPTIONS", "PUT", "DELETE", "CONNECT", "PATCH", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"]
    for unwanted_method in unwanted_methods:
        response = make_request(unwanted_method, full_url, headers, body, proxy)

def inject_parameters(method, full_url, headers, body, param_inject, proxy=None):
    logging.info("Parameter Injection Testing")

    # Parse the URL and extract query parameters
    url_parts = urlparse(full_url)
    query_params = parse_qs(url_parts.query)

    # Inject parameters into the URL query string
    for key in query_params.keys():
        injected_params = query_params.copy()
        injected_params[key] = [param_inject]
        new_query = urlencode(injected_params, doseq=True)
        new_url_parts = url_parts._replace(query=new_query)
        new_url = urlunparse(new_url_parts)
        response = make_request(method, new_url, headers, body, proxy)
        logging.info(f"Injected URL Parameter ({key}) - Status Code: {response.status_code}")

    # Inject parameters into the body based on content type
    content_type = headers.get('Content-Type', '').split(';')[0]  # Normalize content-type

    if content_type == 'application/json':
        params = json.loads(body)
        for key in params.keys():
            injected_params = params.copy()
            injected_params[key] = param_inject
            injected_body = json.dumps(injected_params)
            response = make_request(method, full_url, headers, injected_body, proxy)
            logging.info(f"Injected Body Parameter ({key}) - Status Code: {response.status_code}")

    elif content_type in ['application/xml', 'text/xml']:
        root = ET.fromstring(body)
        for elem in root.iter():
            if elem.text:
                injected_root = ET.fromstring(body)
                injected_elem = injected_root.find(elem.tag)
                injected_elem.text = param_inject
                injected_body = ET.tostring(injected_root, encoding='unicode')
                response = make_request(method, full_url, headers, injected_body, proxy)
                logging.info(f"Injected XML Body Parameter ({elem.tag}) - Status Code: {response.status_code}")

    elif content_type == 'application/x-www-form-urlencoded':
        params = parse_qs(body)
        for key in params.keys():
            injected_params = params.copy()
            injected_params[key] = [param_inject]
            injected_body = urlencode(injected_params, doseq=True)
            response = make_request(method, full_url, headers, injected_body, proxy)
            logging.info(f"Injected Body Parameter ({key}) - Status Code: {response.status_code}")

    elif content_type == 'text/html':
        soup = BeautifulSoup(body, 'html.parser')
        for tag in soup.find_all():
            if tag.string:
                original_text = tag.string
                tag.string.replace_with(param_inject)
                injected_body = str(soup)
                response = make_request(method, full_url, headers, injected_body, proxy)
                logging.info(f"Injected HTML Body Parameter ({tag.name}) - Status Code: {response.status_code}")
                tag.string.replace_with(original_text)  # revert for next iteration

    elif content_type == 'text/plain':
        injected_body = param_inject
        response = make_request(method, full_url, headers, injected_body, proxy)
        logging.info(f"Injected Plain Text Body - Status Code: {response.status_code}")

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
        logging.info(f"Path Traversal Payload ({payload}) - Status Code: {response.status_code}")

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
    parser.add_argument('--log_level', type=str, default='DEBUG', help="Set the logging level (e.g., DEBUG, INFO, WARNING, ERROR, CRITICAL)")

    args = parser.parse_args()
    file_path = args.file_path
    conn = "http://" if args.unsecure else "https://"

    # Set the logging level based on the argument
    log_level = getattr(logging, args.log_level.upper(), logging.DEBUG)

    # Configure logging with color
    log_colors = {
        'DEBUG': 'blue',
        'INFO': 'green',  # changed from 'magenta' to 'green'
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

    # Parse custom headers
    custom_headers = {}
    if args.header:
        for header in args.header:
            key, value = header.split(':', 1)
            custom_headers[key.strip()] = value.strip()

    method, full_url, headers, body, response = convert_raw_http_to_requests(file_path, conn, custom_headers, args.proxy)

    # Print the response
    logging.debug(f"Request - Status Code: {response.status_code} {response.reason}")
    logging.debug(f"Request - Response Length: {len(response.content)}")

    # Inject headers if the hInject argument is provided
    if args.hInject:
        inject_headers(method, full_url, headers, body, args.hInject, args.proxy)

    # Check unwanted HTTP methods if the unwanted_http_check argument is provided
    if args.unwanted_http_check:
        check_unwanted_http_methods(method, full_url, headers, body, args.proxy)

    # Inject parameters if the pInject argument is provided
    if args.pInject:
        inject_parameters(method, full_url, headers, body, args.pInject, args.proxy)

    # Test path traversal if the path_traversal argument is provided
    if args.path_traversal:
        test_path_traversal(method, full_url, headers, body, args.path_traversal, args.proxy)
