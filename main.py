import argparse
import logging
import warnings
import sys
from colorama import init, Fore, Style
from urllib3.exceptions import InsecureRequestWarning
from utils.logging_utils import setup_logging
from utils.request_utils import convert_raw_http_to_requests
from utils.core import parse_status_codes, should_display_status_code
from modules.header_injection import inject_headers, inject_headers_from_file, inject_headers_with_payload_file
from modules.parameter_injection import inject_parameters, inject_parameters_from_file
from modules.path_traversal import test_path_traversal
from modules.http_methods import check_unwanted_http_methods

# Initialize colorama
init()

# Suppress SSL warnings
warnings.simplefilter('ignore', InsecureRequestWarning)

def get_status_color(status_code):
    if status_code >= 500:
        return Fore.RED
    elif status_code >= 400:
        return Fore.YELLOW
    elif status_code >= 300:
        return Fore.CYAN
    elif status_code >= 200:
        return Fore.GREEN
    return Fore.WHITE

def main():
    try:
        parser = argparse.ArgumentParser(description="A security testing tool for analyzing HTTP requests and identifying potential vulnerabilities")
        parser.add_argument('file', help="Path to a file containing a raw HTTP request to analyze")
        parser.add_argument('-u', '--unsecure', action='store_true', help="Use HTTP instead of HTTPS for connections")
        parser.add_argument('-H', '--header', action='append', help="Add custom HTTP header format (e.g. 'Host: example.com')")
        parser.add_argument('-hi', '--header-inject', help="Payload to use for testing header injection vulnerabilities")
        parser.add_argument('-hif', '--header-inject-file', help="File containing header names for testing header injection vulnerabilities")
        parser.add_argument('-hipf', '--header-inject-payload-file', help="File containing payloads to inject into existing headers")
        parser.add_argument('-m', '--methods', action='store_true', help="Test for potentially dangerous HTTP methods like PUT, DELETE, etc.")
        parser.add_argument('-pi', '--param-inject', help="Payload to use for testing parameter injection vulnerabilities")
        parser.add_argument('-pif', '--param-inject-file', help="File containing payloads for testing parameter injection vulnerabilities")
        parser.add_argument('-pt', '--path', help="File containing payloads for testing path traversal vulnerabilities")
        parser.add_argument('-p', '--proxy', help="URL of proxy server to route requests through (e.g. http://127.0.0.1:8080)")
        parser.add_argument('-l', '--log', default='DEBUG', help="Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)")
        parser.add_argument('-t', '--thread', type=int, default=1, help="Number of threads for testing (path traversal, HTTP methods, parameter injection, header injection) (default: 1)")
        parser.add_argument('-sc', '--status-code', help="Filter specific status codes to display (e.g., '200,400,404' or '4xx,5xx'). Default: all status codes")
        parser.add_argument('-nr', '--num-retries', type=int, default=0, help="Number of retries if response is 503 (default: 0)")
        parser.add_argument('-s', '--sleep', type=float, default=0, help="Sleep time between requests in seconds (default: 0)")

        args = parser.parse_args()
        conn = "http://" if args.unsecure else "https://"

        # Parse status code filter
        status_code_filter = parse_status_codes(args.status_code)
        if status_code_filter:
            logging.info(f"🔍 Status code filter: {args.status_code}")

        # Setup logging
        setup_logging(args.log)

        # Parse custom headers
        custom_headers = {}
        if args.header:
            logging.info(f"[+] Custom headers: {args.header}")
            for header in args.header:
                key, value = header.split(':', 1)
                custom_headers[key.strip()] = value.strip()

        method, full_url, headers, body, response = convert_raw_http_to_requests(args.file, conn, custom_headers, args.proxy)

        # Print the response with colored status code
        status_color = get_status_color(response.status_code)
        logging.info(f"[+] Positive Test Request - Status Code: {status_color}{response.status_code} {response.reason}{Style.RESET_ALL}")
        logging.info(f"Request - Response Length: {len(response.content)}")

        # Inject headers - prioritize file-based over single payload
        if args.header_inject_file:
            # File-based header injection with threading
            inject_headers_from_file(method, full_url, headers, body, args.header_inject_file, args.header_inject, args.proxy, args.thread, status_code_filter, args.num_retries, args.sleep)
        elif args.header_inject_payload_file:
            # Payload file injection into existing headers with threading
            inject_headers_with_payload_file(method, full_url, headers, body, args.header_inject_payload_file, args.proxy, args.thread, status_code_filter, args.num_retries, args.sleep)
        elif args.header_inject:
            # Single header injection (existing headers) with threading
            inject_headers(method, full_url, headers, body, args.header_inject, args.proxy, status_code_filter, args.thread, args.num_retries, args.sleep)

        # Check unwanted HTTP methods if the methods argument is provided
        if args.methods:
            check_unwanted_http_methods(method, full_url, headers, body, args.proxy, status_code_filter, args.thread, args.num_retries, args.sleep)

        # Inject parameters if the param-inject argument is provided
        if args.param_inject:
            inject_parameters(method, full_url, headers, body, args.param_inject, args.proxy, status_code_filter, args.num_retries, args.sleep)
        
        # Inject parameters from file if the param-inject-file argument is provided
        if args.param_inject_file:
            inject_parameters_from_file(method, full_url, headers, body, args.param_inject_file, args.proxy, args.thread, status_code_filter, args.num_retries, args.sleep)

        # Test path traversal if the path argument is provided
        if args.path:
            test_path_traversal(method, full_url, headers, body, args.path, args.proxy, args.thread, status_code_filter, args.num_retries, args.sleep)

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Script interrupted by user. Exiting gracefully...{Style.RESET_ALL}")
        sys.exit(0)
    except FileNotFoundError as e:
        print(f"\n{Fore.RED}[!] Error: File not found - {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[!] An unexpected error occurred: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
