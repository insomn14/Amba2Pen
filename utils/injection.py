# amba2pen/injection.py
import json
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
import logging
from .core import HTTPRequestHandler

class HTTPInjector:
    def __init__(self, proxy=None):
        self.request_handler = HTTPRequestHandler(proxy)

    def inject_headers(self, method, full_url, headers, body, header_inject):
        logging.info(f"Header Injection Testing - {header_inject}")
        for key in headers.keys():
            if key.lower() == 'host':
                continue
            injected_headers = headers.copy()
            injected_headers[key] = header_inject
            response = self.request_handler.make_request(method, full_url, injected_headers, body)
            if self.filter_status_code(response.status_code):
                logging.info(f"{method} - {full_url}")
                logging.info(f"Injected Request Headers: ({key}) - Status Code: {response.status_code}")

    def check_unwanted_http_methods(self, method, full_url, headers, body):
        logging.info("Unwanted HTTP Method Check")
        unwanted_methods = ["TRACE", "TRACK", "OPTIONS", "PUT", "DELETE", "CONNECT", "PATCH", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"]
        for unwanted_method in unwanted_methods:
            response = self.request_handler.make_request(unwanted_method, full_url, headers, body)
            if self.filter_status_code(response.status_code):
                logging.info(f"Unwanted HTTP Method ({unwanted_method}) - Status Code: {response.status_code}")

    def inject_parameters(self, method, full_url, headers, body, param_inject):
        logging.info(f"Parameter Injection Testing - {param_inject}")

        try:
            url_parts = urlparse(full_url)
            query_params = parse_qs(url_parts.query)
            if not query_params:
                logging.warning("No query parameters found for injection.")
        except Exception as e:
            logging.error(f"Error parsing URL parameters: {e}")
            return

        for key in query_params.keys():
            try:
                injected_params = query_params.copy()
                injected_params[key] = [param_inject]
                new_query = urlencode(injected_params, doseq=True)
                new_url_parts = url_parts._replace(query=new_query)
                new_url = urlunparse(new_url_parts)
                response = self.request_handler.make_request(method, new_url, headers, body)
                if self.filter_status_code(response.status_code):
                    logging.info(f"{method} - {full_url}")
                    logging.info(f"Injected URL Parameter ({key}) - Status Code: {response.status_code}")
            except Exception as e:
                logging.error(f"Error injecting URL parameter ({key}): {e}")

        content_type = headers.get('Content-Type', '').split(';')[0]

        if content_type == 'application/json':
            self.inject_json_parameters(method, full_url, headers, body, param_inject)

        elif content_type in ['application/xml', 'text/xml']:
            self.inject_xml_parameters(method, full_url, headers, body, param_inject)

        elif content_type == 'application/x-www-form-urlencoded':
            self.inject_form_urlencoded_parameters(method, full_url, headers, body, param_inject)

        elif content_type == 'text/html':
            self.inject_html_parameters(method, full_url, headers, body, param_inject)

        elif content_type == 'text/plain':
            self.inject_plain_text_parameters(method, full_url, headers, body, param_inject)

        else:
            logging.warning(f"Content-Type {content_type} is not supported for parameter injection.")

    def inject_json_parameters(self, method, full_url, headers, body, param_inject):
        try:
            params = json.loads(body)
            if not params:
                logging.warning("No JSON body parameters found for injection.")
                return
            for key in params.keys():
                injected_params = params.copy()
                injected_params[key] = param_inject
                injected_body = json.dumps(injected_params)
                response = self.request_handler.make_request(method, full_url, headers, injected_body)
                if self.filter_status_code(response.status_code):
                    logging.info(f"Injected Body Parameter ({key}) - Status Code: {response.status_code}")
        except Exception as e:
            logging.error(f"Error injecting JSON body parameter: {e}")

    def inject_xml_parameters(self, method, full_url, headers, body, param_inject):
        try:
            root = ET.fromstring(body)
            if not list(root):
                logging.warning("No XML body parameters found for injection.")
                return
            for elem in root.iter():
                if elem.text:
                    injected_root = ET.fromstring(body)
                    injected_elem = injected_root.find(elem.tag)
                    injected_elem.text = param_inject
                    injected_body = ET.tostring(injected_root, encoding='unicode')
                    response = self.request_handler.make_request(method, full_url, headers, injected_body)
                    if self.filter_status_code(response.status_code):
                        logging.info(f"Injected XML Body Parameter ({elem.tag}) - Status Code: {response.status_code}")
        except Exception as e:
            logging.error(f"Error injecting XML body parameter: {e}")

    def inject_form_urlencoded_parameters(self, method, full_url, headers, body, param_inject):
        try:
            params = parse_qs(body)
            if not params:
                logging.warning("No form-urlencoded body parameters found for injection.")
                return
            for key in params.keys():
                injected_params = params.copy()
                injected_params[key] = [param_inject]
                injected_body = urlencode(injected_params, doseq=True)
                response = self.request_handler.make_request(method, full_url, headers, injected_body)
                if self.filter_status_code(response.status_code):
                    logging.info(f"Injected Body Parameter ({key}) - Status Code: {response.status_code}")
        except Exception as e:
            logging.error(f"Error injecting form-urlencoded body parameter: {e}")

    def inject_html_parameters(self, method, full_url, headers, body, param_inject):
        try:
            soup = BeautifulSoup(body, 'html.parser')
            if not soup.find_all():
                logging.warning("No HTML body parameters found for injection.")
                return
            for tag in soup.find_all():
                if tag.string:
                    original_text = tag.string
                    tag.string.replace_with(param_inject)
                    injected_body = str(soup)
                    response = self.request_handler.make_request(method, full_url, headers, injected_body)
                    if self.filter_status_code(response.status_code):
                        logging.info(f"Injected HTML Body Parameter ({tag.name}) - Status Code: {response.status_code}")
                    tag.string.replace_with(original_text)
        except Exception as e:
            logging.error(f"Error injecting HTML body parameter: {e}")

    def inject_plain_text_parameters(self, method, full_url, headers, body, param_inject):
        try:
            if not body.strip():
                logging.warning("No plain text body parameters found for injection.")
                return
            injected_body = param_inject
            response = self.request_handler.make_request(method, full_url, headers, injected_body)
            if self.filter_status_code(response.status_code):
                logging.info(f"Injected Plain Text Body - Status Code: {response.status_code}")
        except Exception as e:
            logging.error(f"Error injecting plain text body parameter: {e}")

    @staticmethod
    def filter_status_code(status_code):
        # Define the criteria for filtering status codes
        return status_code in range(200, 300)