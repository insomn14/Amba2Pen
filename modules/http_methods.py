import logging
import threading
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

def test_single_method(method, full_url, headers, body, proxy=None, status_code_filter=None, num_retries=0, sleep_time=0):
    """Test a single HTTP method"""
    try:
        response = make_request_with_retry(method, full_url, headers, body, proxy, num_retries, 1.5, sleep_time)
        if should_display_status_code(response.status_code, status_code_filter):
            status_color = get_status_color(response.status_code)
            logging.info(f"Method {method} - Status Code: {status_color}{response.status_code}{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"Error testing method {method}: {e}")

def check_unwanted_http_methods(method, full_url, headers, body, proxy=None, status_code_filter=None, num_threads=1, num_retries=0, sleep_time=0):
    logging.info("⚠️ Unwanted HTTP Method Check")
    logging.info(f" Using {num_threads} thread(s)")
    
    unwanted_methods = ["TRACE", "TRACK", "OPTIONS", "PUT", "DELETE", "CONNECT", "PATCH", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"]
    
    logging.info(f"📊 Total methods to test: {len(unwanted_methods)}")
    
    if num_threads == 1:
        # Single thread execution
        for unwanted_method in unwanted_methods:
            test_single_method(unwanted_method, full_url, headers, body, proxy, status_code_filter, num_retries, sleep_time)
    else:
        # Multi-thread execution
        threads = []
        methods_per_thread = len(unwanted_methods) // num_threads
        remaining_methods = len(unwanted_methods) % num_threads
        
        start_idx = 0
        for i in range(num_threads):
            # Calculate methods for this thread
            thread_methods = methods_per_thread
            if i < remaining_methods:
                thread_methods += 1
            
            end_idx = start_idx + thread_methods
            thread_method_list = unwanted_methods[start_idx:end_idx]
            
            # Create and start thread
            thread = threading.Thread(
                target=test_methods_in_thread,
                args=(full_url, headers, body, thread_method_list, proxy, i + 1, status_code_filter, num_retries, sleep_time)
            )
            threads.append(thread)
            thread.start()
            
            start_idx = end_idx
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
    
    logging.info("✅ HTTP methods testing completed")

def test_methods_in_thread(full_url, headers, body, methods, proxy, thread_id, status_code_filter=None, num_retries=0, sleep_time=0):
    """Test methods in a specific thread"""
    # logging.info(f"🧵 Thread {thread_id} started with {len(methods)} methods")
    
    for method in methods:
        test_single_method(method, full_url, headers, body, proxy, status_code_filter, num_retries, sleep_time)
    
    # logging.info(f"🧵 Thread {thread_id} completed")
