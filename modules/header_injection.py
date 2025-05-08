import logging
from utils.request_utils import make_request

def inject_headers(method, full_url, headers, body, header_inject, proxy=None):
    logging.info("Header Injection Testing")
    for key in headers.keys():
        if key.lower() == 'host':
            continue
        injected_headers = headers.copy()
        injected_headers[key] = header_inject
        response = make_request(method, full_url, injected_headers, body, proxy)
        logging.info(f"Injected Request Headers: ({key})")
