import logging
import json
import threading
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
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

def inject_parameters(method, full_url, headers, body, param_inject, proxy=None, status_code_filter=None, num_retries=0, sleep_time=0):
    logging.info("💉 Parameter Injection Testing")

    logging.info(f"Target URI: {full_url}")
    logging.info(f"Payload Inject: {param_inject}")

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
        response = make_request_with_retry(method, new_url, headers, body, proxy, num_retries, 1.5, sleep_time)
        
        if should_display_status_code(response.status_code, status_code_filter):
            status_color = get_status_color(response.status_code)
            logging.info(f"Injected URL Parameter ({key}) - Status Code: {status_color}{response.status_code}{Style.RESET_ALL}")

    # Inject parameters into the body based on content type
    content_type = headers.get('Content-Type', '').split(';')[0]

    if content_type == 'application/json':
        logging.info("🔍 Injecting JSON parameters")
        inject_json_parameters(method, full_url, headers, body, param_inject, proxy, status_code_filter, num_retries, sleep_time)
    elif content_type in ['application/xml', 'text/xml']:
        logging.info("🔍 Injecting XML parameters")
        root = ET.fromstring(body)
        for elem in root.iter():
            if elem.text:
                injected_root = ET.fromstring(body)
                injected_elem = injected_root.find(elem.tag)
                injected_elem.text = param_inject
                injected_body = ET.tostring(injected_root, encoding='unicode')
                response = make_request_with_retry(method, full_url, headers, injected_body, proxy, num_retries, 1.5, sleep_time)
                if should_display_status_code(response.status_code, status_code_filter):
                    status_color = get_status_color(response.status_code)
                    logging.info(f"Injected XML Body Parameter ({elem.tag}) - Status Code: {status_color}{response.status_code}{Style.RESET_ALL}")
    elif content_type == 'application/x-www-form-urlencoded':
        logging.info("🔍 Injecting Form URL Encoded parameters")
        params = parse_qs(body)
        for key in params.keys():
            injected_params = params.copy()
            injected_params[key] = [param_inject]
            injected_body = urlencode(injected_params, doseq=True)
            response = make_request_with_retry(method, full_url, headers, injected_body, proxy, num_retries, 1.5, sleep_time)
            if should_display_status_code(response.status_code, status_code_filter):
                status_color = get_status_color(response.status_code)
                logging.info(f"Injected Body Parameter ({key}) - Status Code: {status_color}{response.status_code}{Style.RESET_ALL}")
    elif content_type == 'text/html':
        logging.info("🔍 Injecting HTML parameters")
        soup = BeautifulSoup(body, 'html.parser')
        for tag in soup.find_all():
            if tag.string:
                original_text = tag.string
                tag.string.replace_with(param_inject)
                injected_body = str(soup)
                response = make_request_with_retry(method, full_url, headers, injected_body, proxy, num_retries, 1.5, sleep_time)
                if should_display_status_code(response.status_code, status_code_filter):
                    status_color = get_status_color(response.status_code)
                    logging.info(f"Injected HTML Body Parameter ({tag.name}) - Status Code: {status_color}{response.status_code}{Style.RESET_ALL}")
                tag.string.replace_with(original_text)  # revert for next iteration
    elif content_type == 'text/plain':
        logging.info("🔍 Injecting Plain Text parameters")
        injected_body = param_inject
        response = make_request_with_retry(method, full_url, headers, injected_body, proxy, num_retries, 1.5, sleep_time)
        if should_display_status_code(response.status_code, status_code_filter):
            status_color = get_status_color(response.status_code)
            logging.info(f"Injected Plain Text Body - Status Code: {status_color}{response.status_code}{Style.RESET_ALL}")
    elif content_type == 'application/octet-stream':
        logging.warning("Parameter injection for application/octet-stream is not supported.")
    elif content_type == 'application/javascript':
        logging.warning("Parameter injection for application/javascript is not supported.")
    else:
        logging.warning(f"Content-Type {content_type} is not supported for parameter injection.")

def inject_parameters_from_file(method, full_url, headers, body, payload_file, proxy=None, num_threads=1, status_code_filter=None, num_retries=0, sleep_time=0):
    logging.info("💉 Parameter Injection Testing (File-based)")
    logging.info(f"🔧 Using {num_threads} thread(s)")

    try:
        with open(payload_file, 'r') as file:
            payloads = [line.strip() for line in file.readlines() if line.strip()]

        if not payloads:
            logging.warning("No payloads found in the file.")
            return

        logging.info(f"Target URI: {full_url}")
        logging.info(f"📊 Total payloads to test: {len(payloads)}")

        if num_threads == 1:
            # Single thread execution
            for payload in payloads:
                inject_single_payload(method, full_url, headers, body, payload, proxy, status_code_filter, num_retries, sleep_time)
        else:
            # Multi-thread execution
            threads = []
            payloads_per_thread = len(payloads) // num_threads
            remaining_payloads = len(payloads) % num_threads

            start_idx = 0
            for i in range(num_threads):
                # Calculate payloads for this thread
                thread_payloads = payloads_per_thread
                if i < remaining_payloads:
                    thread_payloads += 1

                end_idx = start_idx + thread_payloads
                thread_payload_list = payloads[start_idx:end_idx]

                # Create and start thread
                thread = threading.Thread(
                    target=inject_payloads_in_thread,
                    args=(method, full_url, headers, body, thread_payload_list, proxy, i + 1, status_code_filter, num_retries, sleep_time)
                )
                threads.append(thread)
                thread.start()

                start_idx = end_idx

            # Wait for all threads to complete
            for thread in threads:
                thread.join()

        logging.info("✅ Parameter injection testing completed")

    except FileNotFoundError:
        logging.error(f"Payload file not found: {payload_file}")
    except Exception as e:
        logging.error(f"Error during parameter injection testing: {e}")

def inject_single_payload(method, full_url, headers, body, payload, proxy=None, status_code_filter=None, num_retries=0, sleep_time=0):
    """Inject a single payload into all parameters"""
    try:
        # Parse the URL and extract query parameters
        url_parts = urlparse(full_url)
        query_params = parse_qs(url_parts.query)

        # Inject payload into URL query parameters
        for key in query_params.keys():
            injected_params = query_params.copy()
            injected_params[key] = [payload]
            new_query = urlencode(injected_params, doseq=True)
            new_url_parts = url_parts._replace(query=new_query)
            new_url = urlunparse(new_url_parts)
            response = make_request_with_retry(method, new_url, headers, body, proxy, num_retries, 1.5, sleep_time)
            
            if should_display_status_code(response.status_code, status_code_filter):
                status_color = get_status_color(response.status_code)
                logging.info(f"Payload '{payload}' -> URL Param ({key}) - Status Code: {status_color}{response.status_code}{Style.RESET_ALL}")

        # Inject payload into body parameters based on content type
        content_type = headers.get('Content-Type', '').split(';')[0]

        if content_type == 'application/json':
            inject_json_payload(method, full_url, headers, body, payload, proxy, status_code_filter, num_retries, sleep_time)
        elif content_type in ['application/xml', 'text/xml']:
            inject_xml_payload(method, full_url, headers, body, payload, proxy, status_code_filter, num_retries, sleep_time)
        elif content_type == 'application/x-www-form-urlencoded':
            inject_form_payload(method, full_url, headers, body, payload, proxy, status_code_filter, num_retries, sleep_time)
        elif content_type == 'text/html':
            inject_html_payload(method, full_url, headers, body, payload, proxy, status_code_filter, num_retries, sleep_time)
        elif content_type == 'text/plain':
            inject_plain_payload(method, full_url, headers, body, payload, proxy, status_code_filter, num_retries, sleep_time)

    except Exception as e:
        logging.error(f"Error injecting payload '{payload}': {e}")

def inject_payloads_in_thread(method, full_url, headers, body, payloads, proxy, thread_id, status_code_filter=None, num_retries=0, sleep_time=0):
    """Inject payloads in a specific thread"""
    # logging.info(f"🧵 Thread {thread_id} started with {len(payloads)} payloads")
    
    for payload in payloads:
        inject_single_payload(method, full_url, headers, body, payload, proxy, status_code_filter, num_retries, sleep_time)
    
    # logging.info(f"🧵 Thread {thread_id} completed")

def inject_json_payload(method, full_url, headers, body, payload, proxy=None, status_code_filter=None, num_retries=0, sleep_time=0):
    """Inject payload into JSON body parameters"""
    try:
        params = json.loads(body)
        if not params:
            return

        def inject_nested_json(data, path=""):
            if isinstance(data, dict):
                for key, value in data.items():
                    current_path = f"{path}.{key}" if path else key
                    # Inject into current key
                    injected_data = json.loads(body)  # Create fresh copy
                    current = injected_data
                    if path:
                        for p in path.split('.'):
                            current = current[p]
                    current[key] = payload
                    injected_body = json.dumps(injected_data)
                    response = make_request_with_retry(method, full_url, headers, injected_body, proxy, num_retries, 1.5, sleep_time)
                    if should_display_status_code(response.status_code, status_code_filter):
                        status_color = get_status_color(response.status_code)
                        logging.info(f"Payload '{payload}' -> JSON Param ({current_path}) - Status Code: {status_color}{response.status_code}{Style.RESET_ALL}")
                    # Recursively process nested objects
                    if isinstance(value, (dict, list)):
                        inject_nested_json(value, current_path)
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    current_path = f"{path}[{i}]"
                    if isinstance(item, (dict, list)):
                        inject_nested_json(item, current_path)

        inject_nested_json(params)

    except Exception as e:
        logging.error(f"Error injecting JSON payload '{payload}': {e}")

def inject_xml_payload(method, full_url, headers, body, payload, proxy=None, status_code_filter=None, num_retries=0, sleep_time=0):
    """Inject payload into XML body parameters"""
    try:
        root = ET.fromstring(body)
        for elem in root.iter():
            if elem.text:
                injected_root = ET.fromstring(body)
                injected_elem = injected_root.find(elem.tag)
                injected_elem.text = payload
                injected_body = ET.tostring(injected_root, encoding='unicode')
                response = make_request_with_retry(method, full_url, headers, injected_body, proxy, num_retries, 1.5, sleep_time)
                if should_display_status_code(response.status_code, status_code_filter):
                    status_color = get_status_color(response.status_code)
                    logging.info(f"Payload '{payload}' -> XML Param ({elem.tag}) - Status Code: {status_color}{response.status_code}{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"Error injecting XML payload '{payload}': {e}")

def inject_form_payload(method, full_url, headers, body, payload, proxy=None, status_code_filter=None, num_retries=0, sleep_time=0):
    """Inject payload into form URL encoded parameters"""
    try:
        params = parse_qs(body)
        for key in params.keys():
            injected_params = params.copy()
            injected_params[key] = [payload]
            injected_body = urlencode(injected_params, doseq=True)
            response = make_request_with_retry(method, full_url, headers, injected_body, proxy, num_retries, 1.5, sleep_time)
            if should_display_status_code(response.status_code, status_code_filter):
                status_color = get_status_color(response.status_code)
                logging.info(f"Payload '{payload}' -> Form Param ({key}) - Status Code: {status_color}{response.status_code}{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"Error injecting form payload '{payload}': {e}")

def inject_html_payload(method, full_url, headers, body, payload, proxy=None, status_code_filter=None, num_retries=0, sleep_time=0):
    """Inject payload into HTML body parameters"""
    try:
        soup = BeautifulSoup(body, 'html.parser')
        for tag in soup.find_all():
            if tag.string:
                original_text = tag.string
                tag.string.replace_with(payload)
                injected_body = str(soup)
                response = make_request_with_retry(method, full_url, headers, injected_body, proxy, num_retries, 1.5, sleep_time)
                if should_display_status_code(response.status_code, status_code_filter):
                    status_color = get_status_color(response.status_code)
                    logging.info(f"Payload '{payload}' -> HTML Param ({tag.name}) - Status Code: {status_color}{response.status_code}{Style.RESET_ALL}")
                tag.string.replace_with(original_text)  # revert for next iteration
    except Exception as e:
        logging.error(f"Error injecting HTML payload '{payload}': {e}")

def inject_plain_payload(method, full_url, headers, body, payload, proxy=None, status_code_filter=None, num_retries=0, sleep_time=0):
    """Inject payload into plain text body"""
    try:
        injected_body = payload
        response = make_request_with_retry(method, full_url, headers, injected_body, proxy, num_retries, 1.5, sleep_time)
        if should_display_status_code(response.status_code, status_code_filter):
            status_color = get_status_color(response.status_code)
            logging.info(f"Payload '{payload}' -> Plain Text - Status Code: {status_color}{response.status_code}{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"Error injecting plain text payload '{payload}': {e}")

def inject_json_parameters(method, full_url, headers, body, param_inject, proxy=None, status_code_filter=None, num_retries=0, sleep_time=0):
    try:
        params = json.loads(body)
        if not params:
            logging.warning("No JSON body parameters found for injection.")
            return

        def inject_nested_params(data, path=""):
            if isinstance(data, dict):
                for key, value in data.items():
                    current_path = f"{path}.{key}" if path else key
                    # Inject into current key
                    injected_data = json.loads(body)  # Create fresh copy
                    current = injected_data
                    if path:
                        for p in path.split('.'):
                            current = current[p]
                    current[key] = param_inject
                    injected_body = json.dumps(injected_data)
                    response = make_request_with_retry(method, full_url, headers, injected_body, proxy, num_retries, 1.5, sleep_time)
                    if should_display_status_code(response.status_code, status_code_filter):
                        status_color = get_status_color(response.status_code)
                        logging.info(f"Injected Body Parameter ({current_path}) - Status Code: {status_color}{response.status_code}{Style.RESET_ALL}")
                    # Recursively process nested objects
                    if isinstance(value, (dict, list)):
                        inject_nested_params(value, current_path)
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    current_path = f"{path}[{i}]"
                    if isinstance(item, (dict, list)):
                        inject_nested_params(item, current_path)

        inject_nested_params(params)

    except Exception as e:
        logging.error(f"Error injecting JSON body parameter: {e}")
