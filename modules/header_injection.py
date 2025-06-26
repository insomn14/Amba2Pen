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

def inject_headers(method, full_url, headers, body, header_inject, proxy=None, status_code_filter=None, num_threads=1, num_retries=0, sleep_time=0):
    logging.info("✉️ Header Injection Testing")
    logging.info(f"🔧 Using {num_threads} thread(s)")

    logging.info(f"Target URI: {full_url}")
    logging.info(f"Payload Inject: {header_inject}")

    # Get all headers except 'host'
    header_keys = [key for key in headers.keys() if key.lower() != 'host']
    
    logging.info(f"📊 Total headers to test: {len(header_keys)}")

    if num_threads == 1:
        # Single thread execution
        for key in header_keys:
            injected_headers = headers.copy()
            # original_value = headers[key]
            # injected_headers[key] = f"{original_value}{header_inject}"
            injected_headers[key] = f"{header_inject}"
            response = make_request_with_retry(method, full_url, injected_headers, body, proxy, num_retries, 1.5, sleep_time)
            if should_display_status_code(response.status_code, status_code_filter):
                status_color = get_status_color(response.status_code)
                logging.info(f"Injected Request Headers: ({key}) - Status Code: {status_color}{response.status_code}{Style.RESET_ALL}")
    else:
        # Multi-thread execution
        threads = []
        headers_per_thread = len(header_keys) // num_threads
        remaining_headers = len(header_keys) % num_threads

        start_idx = 0
        for i in range(num_threads):
            # Calculate headers for this thread
            thread_headers = headers_per_thread
            if i < remaining_headers:
                thread_headers += 1

            end_idx = start_idx + thread_headers
            thread_header_list = header_keys[start_idx:end_idx]

            # Create and start thread
            thread = threading.Thread(
                target=inject_existing_headers_in_thread,
                args=(method, full_url, headers, body, thread_header_list, header_inject, proxy, i + 1, status_code_filter, num_retries, sleep_time)
            )
            threads.append(thread)
            thread.start()

            start_idx = end_idx

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

    logging.info("✅ Header injection testing completed")

def inject_existing_headers_in_thread(method, full_url, headers, body, header_keys, payload, proxy, thread_id, status_code_filter=None, num_retries=0, sleep_time=0):
    """Inject payload into existing headers in a specific thread"""
    # logging.info(f"🧵 Thread {thread_id} started with {len(header_keys)} headers")
    
    for key in header_keys:
        injected_headers = headers.copy()
        # original_value = headers[key]
        # injected_headers[key] = f"{original_value}{payload}"
        injected_headers[key] = f"{payload}"
        response = make_request_with_retry(method, full_url, injected_headers, body, proxy, num_retries, 1.5, sleep_time)
        if should_display_status_code(response.status_code, status_code_filter):
            status_color = get_status_color(response.status_code)
            logging.info(f"Injected Request Headers: ({key}) - Status Code: {status_color}{response.status_code}{Style.RESET_ALL}")
    
    # logging.info(f"🧵 Thread {thread_id} completed")

def inject_headers_from_file(method, full_url, headers, body, header_file, payload, proxy=None, num_threads=1, status_code_filter=None, num_retries=0, sleep_time=0):
    logging.info("✉️ Header Injection Testing (File-based)")
    logging.info(f"🔧 Using {num_threads} thread(s)")

    try:
        with open(header_file, 'r') as file:
            # Clean header names by removing trailing ':' or ': '
            header_names = []
            for line in file.readlines():
                line = line.strip()
                if line:
                    # Remove trailing ':' or ': ' from header names
                    header_name = line.rstrip(': ').rstrip(':')
                    if header_name:  # Only add if header name is not empty after cleaning
                        header_names.append(header_name)

        if not header_names:
            logging.warning("No valid header names found in the file.")
            return

        logging.info(f"Target URI: {full_url}")
        logging.info(f"Payload Inject: {payload}")
        logging.info(f"📊 Total headers to test: {len(header_names)}")

        if num_threads == 1:
            # Single thread execution
            for header_name in header_names:
                inject_single_header(method, full_url, headers, body, header_name, payload, proxy, status_code_filter, num_retries, sleep_time)
        else:
            # Multi-thread execution
            threads = []
            headers_per_thread = len(header_names) // num_threads
            remaining_headers = len(header_names) % num_threads

            start_idx = 0
            for i in range(num_threads):
                # Calculate headers for this thread
                thread_headers = headers_per_thread
                if i < remaining_headers:
                    thread_headers += 1

                end_idx = start_idx + thread_headers
                thread_header_list = header_names[start_idx:end_idx]

                # Create and start thread
                thread = threading.Thread(
                    target=inject_headers_in_thread,
                    args=(method, full_url, headers, body, thread_header_list, payload, proxy, i + 1, status_code_filter, num_retries, sleep_time)
                )
                threads.append(thread)
                thread.start()

                start_idx = end_idx

            # Wait for all threads to complete
            for thread in threads:
                thread.join()

        logging.info("✅ Header injection testing completed")

    except FileNotFoundError:
        logging.error(f"Header file not found: {header_file}")
    except Exception as e:
        logging.error(f"Error during header injection testing: {e}")

def inject_single_header(method, full_url, headers, body, header_name, payload, proxy=None, status_code_filter=None, num_retries=0, sleep_time=0):
    """Inject payload into a single header"""
    try:
        injected_headers = headers.copy()
        injected_headers[header_name] = payload
        response = make_request_with_retry(method, full_url, injected_headers, body, proxy, num_retries, 1.5, sleep_time)
        if should_display_status_code(response.status_code, status_code_filter):
            status_color = get_status_color(response.status_code)
            logging.info(f"Header '{header_name}: {payload}' - Status Code: {status_color}{response.status_code}{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"Error injecting header '{header_name}': {e}")

def inject_headers_in_thread(method, full_url, headers, body, header_names, payload, proxy, thread_id, status_code_filter=None, num_retries=0, sleep_time=0):
    """Inject headers in a specific thread"""
    # logging.info(f"🧵 Thread {thread_id} started with {len(header_names)} headers")
    
    for header_name in header_names:
        inject_single_header(method, full_url, headers, body, header_name, payload, proxy, status_code_filter, num_retries, sleep_time)
    
    # logging.info(f"🧵 Thread {thread_id} completed")

def inject_headers_with_payload_file(method, full_url, headers, body, payload_file, proxy=None, num_threads=1, status_code_filter=None, num_retries=0, sleep_time=0):
    logging.info("✉️ Header Injection Testing (Payload File)")
    logging.info(f"🔧 Using {num_threads} thread(s)")

    try:
        with open(payload_file, 'r') as file:
            payloads = [line.strip() for line in file.readlines() if line.strip()]

        if not payloads:
            logging.warning("No payloads found in the file.")
            return

        # Get all headers except 'host'
        header_keys = [key for key in headers.keys() if key.lower() != 'host']

        logging.info(f"Target URI: {full_url}")
        logging.info(f"📊 Total headers to test: {len(header_keys)}")
        logging.info(f"📊 Total payloads to test: {len(payloads)}")
        logging.info(f"📊 Total combinations: {len(header_keys) * len(payloads)}")

        if num_threads == 1:
            # Single thread execution
            for payload in payloads:
                for header_key in header_keys:
                    inject_single_header_payload(method, full_url, headers, body, header_key, payload, proxy, status_code_filter, num_retries, sleep_time)
        else:
            # Multi-thread execution
            # Create combinations of headers and payloads
            combinations = []
            for payload in payloads:
                for header_key in header_keys:
                    combinations.append((header_key, payload))

            threads = []
            combinations_per_thread = len(combinations) // num_threads
            remaining_combinations = len(combinations) % num_threads

            start_idx = 0
            for i in range(num_threads):
                # Calculate combinations for this thread
                thread_combinations = combinations_per_thread
                if i < remaining_combinations:
                    thread_combinations += 1

                end_idx = start_idx + thread_combinations
                thread_combination_list = combinations[start_idx:end_idx]

                # Create and start thread
                thread = threading.Thread(
                    target=inject_header_payloads_in_thread,
                    args=(method, full_url, headers, body, thread_combination_list, proxy, i + 1, status_code_filter, num_retries, sleep_time)
                )
                threads.append(thread)
                thread.start()

                start_idx = end_idx

            # Wait for all threads to complete
            for thread in threads:
                thread.join()

        logging.info("✅ Header injection testing completed")

    except FileNotFoundError:
        logging.error(f"Payload file not found: {payload_file}")
    except Exception as e:
        logging.error(f"Error during header injection testing: {e}")

def inject_single_header_payload(method, full_url, headers, body, header_key, payload, proxy=None, status_code_filter=None, num_retries=0, sleep_time=0):
    """Inject a single payload into a single header"""
    try:
        injected_headers = headers.copy()
        injected_headers[header_key] = payload
        response = make_request_with_retry(method, full_url, injected_headers, body, proxy, num_retries, 1.5, sleep_time)
        if should_display_status_code(response.status_code, status_code_filter):
            status_color = get_status_color(response.status_code)
            logging.info(f"Header '{header_key}: {payload}' - Status Code: {status_color}{response.status_code}{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"Error injecting payload '{payload}' into header '{header_key}': {e}")

def inject_header_payloads_in_thread(method, full_url, headers, body, combinations, proxy, thread_id, status_code_filter=None, num_retries=0, sleep_time=0):
    """Inject payloads into headers in a specific thread"""
    # logging.info(f"🧵 Thread {thread_id} started with {len(combinations)} combinations")
    
    for header_key, payload in combinations:
        inject_single_header_payload(method, full_url, headers, body, header_key, payload, proxy, status_code_filter, num_retries, sleep_time)
    
    # logging.info(f"🧵 Thread {thread_id} completed")
