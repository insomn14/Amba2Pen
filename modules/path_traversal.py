import logging
import threading
from urllib.parse import urlparse, urlunparse
from colorama import Fore, Style
from utils.request_utils import make_request_with_retry
from utils.core import should_display_status_code

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

def test_single_payload(method, full_url, headers, body, payload, proxy=None, status_code_filter=None, num_retries=0, sleep_time=0):
    """Test a single path traversal payload"""
    try:
        # Parse the URL and append the payload to the path
        url_parts = urlparse(full_url)
        new_path = url_parts.path + payload
        new_url_parts = url_parts._replace(path=new_path)
        new_url = urlunparse(new_url_parts)

        response = make_request_with_retry(method, new_url, headers, body, proxy, num_retries, 1.5, sleep_time)
        if should_display_status_code(response.status_code, status_code_filter):
            status_color = get_status_color(response.status_code)
            logging.info(f"Path Traversal Payload ({payload}) - Status Code: {status_color}{response.status_code}{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"Error testing payload {payload}: {e}")

def test_path_traversal(method, full_url, headers, body, payload_file, proxy=None, num_threads=1, status_code_filter=None, num_retries=0, sleep_time=0):
    logging.info("📂 Path Traversal Testing")
    logging.info(f"🔧 Using {num_threads} thread(s)")

    try:
        with open(payload_file, 'r') as file:
            payloads = [line.strip() for line in file.readlines() if line.strip()]

        if not payloads:
            logging.warning("No payloads found in the file.")
            return

        logging.info(f"📊 Total payloads to test: {len(payloads)}")

        if num_threads == 1:
            # Single thread execution
            for payload in payloads:
                test_single_payload(method, full_url, headers, body, payload, proxy, status_code_filter, num_retries, sleep_time)
        else:
            # Multi-thread execution
            threads = []
            chunk_size = len(payloads) // num_threads
            remaining_payloads = len(payloads) % num_threads

            for i in range(num_threads):
                start_index = i * chunk_size
                end_index = (i + 1) * chunk_size if i < num_threads - 1 else len(payloads)
                thread_payloads = payloads[start_index:end_index]
                thread = threading.Thread(target=test_path_traversal_thread, args=(method, full_url, headers, body, thread_payloads, proxy, status_code_filter, num_retries, sleep_time), daemon=True)
                threads.append(thread)
                thread.start()

            # Wait for all threads to complete
            for thread in threads:
                thread.join()

        logging.info("✅ Path traversal testing completed")

    except FileNotFoundError:
        logging.error(f"Payload file not found: {payload_file}")
    except Exception as e:
        logging.error(f"Error during path traversal testing: {e}")

def test_path_traversal_thread(method, full_url, headers, body, payloads, proxy, status_code_filter, num_retries, sleep_time):
    """Test payloads in a specific thread"""
    # logging.info(f"🧵 Thread {thread_id} started with {len(payloads)} payloads")
    
    for payload in payloads:
        test_single_payload(method, full_url, headers, body, payload, proxy, status_code_filter, num_retries, sleep_time)
    
    # logging.info(f"🧵 Thread {thread_id} completed")
