import logging
from urllib.parse import urlparse, urlunparse
from utils.request_utils import make_request

def test_path_traversal(method, full_url, headers, body, payload_file, proxy=None):
    logging.info("Path Traversal Testing")

    with open(payload_file, 'r') as file:
        payloads = file.readlines()

    for payload in payloads:
        payload = payload.strip()

        # Parse the URL and append the payload to the path
        url_parts = urlparse(full_url)
        new_path = url_parts.path + payload
        new_url_parts = url_parts._replace(path=new_path)
        new_url = urlunparse(new_url_parts)

        response = make_request(method, new_url, headers, body, proxy)
        logging.info(f"Path Traversal Payload ({payload}) - Status Code: {response.status_code}")
