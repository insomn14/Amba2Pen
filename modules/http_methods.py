import logging
from utils.request_utils import make_request

def check_unwanted_http_methods(method, full_url, headers, body, proxy=None):
    logging.info("Unwanted HTTP Method Check")
    unwanted_methods = ["TRACE", "TRACK", "OPTIONS", "PUT", "DELETE", "CONNECT", "PATCH", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"]
    for unwanted_method in unwanted_methods:
        response = make_request(unwanted_method, full_url, headers, body, proxy)
