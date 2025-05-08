import logging
import json
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from utils.request_utils import make_request

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
