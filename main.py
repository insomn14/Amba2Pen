import argparse
import logging
import warnings
from urllib3.exceptions import InsecureRequestWarning
from utils.logging_utils import setup_logging
from utils.request_utils import convert_raw_http_to_requests
from modules.header_injection import inject_headers
from modules.parameter_injection import inject_parameters
from modules.path_traversal import test_path_traversal
from modules.http_methods import check_unwanted_http_methods

# Suppress SSL warnings
warnings.simplefilter('ignore', InsecureRequestWarning)

def main():
    parser = argparse.ArgumentParser(description="A security testing tool for analyzing HTTP requests and identifying potential vulnerabilities")
    parser.add_argument('file', help="Path to a file containing a raw HTTP request to analyze")
    parser.add_argument('-u', '--unsecure', action='store_true', help="Use HTTP instead of HTTPS for connections")
    parser.add_argument('-H', '--header', action='append', help="Add custom HTTP header format (e.g. 'Host: example.com')")
    parser.add_argument('-hi', '--header-inject', help="Payload to use for testing header injection vulnerabilities")
    parser.add_argument('-m', '--methods', action='store_true', help="Test for potentially dangerous HTTP methods like PUT, DELETE, etc.")
    parser.add_argument('-pi', '--param-inject', help="Payload to use for testing parameter injection vulnerabilities") 
    parser.add_argument('-pt', '--path', help="File containing payloads for testing path traversal vulnerabilities")
    parser.add_argument('-p', '--proxy', help="URL of proxy server to route requests through (e.g. http://127.0.0.1:8080)")
    parser.add_argument('-l', '--log', default='DEBUG', help="Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)")

    args = parser.parse_args()
    conn = "http://" if args.unsecure else "https://"

    # Setup logging
    setup_logging(args.log_level)

    # Parse custom headers
    custom_headers = {}
    if args.header:
        for header in args.header:
            key, value = header.split(':', 1)
            custom_headers[key.strip()] = value.strip()

    method, full_url, headers, body, response = convert_raw_http_to_requests(args.file_path, conn, custom_headers, args.proxy)

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

if __name__ == "__main__":
    main()
