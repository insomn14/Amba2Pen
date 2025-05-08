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
