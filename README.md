# Amba2PEN (I'm About to Pentest)

Amba2PEN is a Python-based tool designed to streamline the penetration testing process by automating various pentest tasks. This tool allows pentesters to conduct multiple tests directly from the terminal, minimizing repetitive actions and improving efficiency.

## Features

- **Raw HTTP Request Conversion:** Converts raw HTTP requests to Python `requests` calls for ease of testing and modification.
- **Header Injection:** Inject custom headers into HTTP requests to test for header-related vulnerabilities.
- **Parameter Injection:** Inject custom parameters into both URL query strings and request bodies to test for parameter manipulation vulnerabilities.
- **Unwanted HTTP Method Testing:** Check for the presence of unwanted and potentially dangerous HTTP methods on the target server.
- **Path Traversal Testing:** Automatically test for path traversal vulnerabilities using a list of payloads.
- **Proxy Support:** Allows the use of proxy servers to route HTTP requests through intermediaries.
- **Custom Logging:** Configurable logging with color-coded output for better readability and debugging.

## Pros

- **Automation:** Reduces the repetitive nature of common pentest tasks, allowing pentesters to focus on more complex testing.
- **Flexibility:** Supports custom headers, proxies, and payloads, making it adaptable to various testing scenarios.
- **Efficiency:** Combines multiple testing functionalities into one script, saving time and effort.
- **Customization:** Easily extendable to include additional tests or modify existing ones as per requirements.
- **Terminal-Based:** Designed to run entirely from the terminal, fitting seamlessly into existing pentest workflows.

## Cons

- **Limited Content-Type Support:** Parameter injection supports a limited set of content types (JSON, XML, form-urlencoded, HTML, and plain text).
- **Basic Logging:** While color-coded, the logging might not be detailed enough for complex debugging.
- **Initial Setup:** Requires a good understanding of HTTP requests and penetration testing to set up and use effectively.
- **Proxy Configuration:** Proxy setup might require additional configuration, especially in complex network environments.

## Installation

1. **Clone the repository:**
    ```bash
    git clone https://github.com/yourusername/amba2pen.git
    cd amba2pen
    ```

2. **Install the required dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

Run the script with the required arguments to perform various pentest tasks. For example, to convert a raw HTTP request:

```
python amba2pen.py raw_request.txt --header "Custom-Header: value" --proxy "http://proxy.example.com:8080" --log_level DEBUG
```

For path traversal testing:

```
python amba2pen.py raw_request.txt --path_traversal payloads.txt
```

### Command-Line Arguments

- `file_path`: Path to the file containing the raw HTTP request.
- `--unsecure`: Use HTTP instead of HTTPS.
- `--header`: Custom header in the form key:value. Can be used multiple times.
- `--hInject`: Header value to inject into each header one by one.
- `--proxy`: Proxy server (e.g., http://proxy.example.com:8080).
- `--unwanted_http_check`: Check unwanted HTTP methods.
- `--pInject`: Parameter value to inject into each parameter one by one.
- `--path_traversal`: Path to the file containing path traversal payloads.
- `--log_level`: Set the logging level (e.g., DEBUG, INFO, WARNING, ERROR, CRITICAL).

## Examples

### Convert Raw HTTP Request to Python Requests Call

```
python amba2pen.py raw_request.txt --header "Custom-Header: value" --proxy "http://proxy.example.com:8080" --log_level DEBUG
```

### Inject Custom Headers

```
python amba2pen.py raw_request.txt --hInject "Injected-Header-Value" --log_level INFO
```

### Check for Unwanted HTTP Methods

```
python amba2pen.py raw_request.txt --unwanted_http_check --log_level INFO
```

### Inject Custom Parameters

```
python amba2pen.py raw_request.txt --pInject "Injected-Parameter-Value" --log_level INFO
```

### Path Traversal Testing

To test for path traversal vulnerabilities, you can use the --path_traversal argument. This feature reads a list of payloads from a specified file and tests each one against the target URL.

```
python amba2pen.py raw_request.txt --path_traversal path_traversal_payloads.txt --log_level INFO
```

### Path Traversal Payloads File

Create a file with path traversal payloads, each on a new line:
```
../../etc/passwd
../../../../windows/system32/drivers/etc/hosts
../windows/system32/config/sam
../../../../../../../../../../../../../etc/passwd
```

## Contributing

Contributions are welcome! To contribute:

	1.	Fork the repository.
	2.	Create a new branch for your feature.
	3.	Make your changes.
	4.	Submit a pull request.

Please ensure your code adheres to the existing coding standards and includes appropriate tests.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Acknowledgments

 * Thanks to the open-source community for providing various libraries and tools that made this project possible.
 * Special thanks to BeautifulSoup, requests, and colorlog for their excellent libraries.

Happy pentesting with Amba2PEN!
