# Amba2Pen - Advanced Security Testing Tool

Amba2Pen is a powerful security testing tool for analyzing and testing various types of vulnerability injection in HTTP requests. This tool is designed for pentesters and security researchers who need automation in testing API or WEB Application security.

## 🚀 Features

### 🔧 Core Features
- **Raw HTTP Request Processing**: Reads and processes raw HTTP requests from files
- **Multi-Threading Support**: Parallel testing for optimal performance
- **Retry Mechanism**: Automatically retries for 503/596 responses
- **Sleep Control**: Delay between requests for stealth testing
- **Status Code Filtering**: Filters output based on status code
- **Colored Output**: Colored status codes for easy reading
- **Exception Handling**: Graceful error handling and keyboard interrupt support

### 💉 Injection Testing
- **Header Injection**: Testing header injection vulnerabilities
- **Parameter Injection**: Testing parameter injection on various content types (JSON, XML, Forms, HTML, Plain Text)
- **Path Traversal**: Tests for path traversal vulnerabilities
- **HTTP Methods**: Tests malicious HTTP methods (TRACE, TRACK, OPTIONS, PUT, DELETE, etc.)

Translated with DeepL.com (free version)

### 📁 File-Based Testing
- **Header Names File**: Test custom header names dari file
- **Payload Files**: Test multiple payloads dari file
- **Path Traversal Payloads**: Test path traversal dengan payload file
- **Smart Header Parsing**: Auto-clean headers ending with ':' or ': '

## 📦 Installation

### Prerequisites
```bash
# Python 3.7+
python3 --version

# Install dependencies
pip install requests colorama beautifulsoup4 colorlog
```

### Setup
```bash
# Clone repository
git clone <repository-url>
cd Amba2Pen

# Install dependencies
pip install -r requirements.txt
```

## 🎯 Usage

### Basic Syntax
```bash
python3 main.py <request_file> [options]
```

### Arguments Overview

| Argument | Description | Example |
|----------|-------------|---------|
| `file` | Raw HTTP request file | `request.txt` |
| `-u, --unsecure` | Use HTTP instead of HTTPS | `-u` |
| `-H, --header` | Add custom headers | `-H "Host: example.com"` |
| `-hi, --header-inject` | Single header injection | `-hi "payload"` |
| `-hif, --header-inject-file` | Header names from file | `-hif headers.txt` |
| `-hipf, --header-inject-payload-file` | Payloads from file to existing headers | `-hipf payloads.txt` |
| `-pi, --param-inject` | Single parameter injection | `-pi "payload"` |
| `-pif, --param-inject-file` | Payloads from file for parameters | `-pif payloads.txt` |
| `-pt, --path` | Path traversal testing | `-pt payloads.txt` |
| `-m, --methods` | Test dangerous HTTP methods | `-m` |
| `-p, --proxy` | Proxy server | `-p "http://127.0.0.1:8080"` |
| `-t, --thread` | Number of threads | `-t 10` |
| `-s, --sleep` | Sleep between requests (seconds) | `-s 1.5` |
| `-nr, --num-retries` | Retry count for 503/596 responses | `-nr 5` |
| `-sc, --status-code` | Filter status codes | `-sc "200,500"` |
| `-l, --log` | Logging level | `-l INFO` |

## 🔍 Testing Modes

### 1. Header Injection Testing

#### Single Header Injection (Existing Headers)
```bash
# Test existing headers with single payload
python3 main.py request.txt -hi "<script>alert(1);</script>" -t 5
```

#### Custom Headers from File
```bash
# Test custom headers from file
python3 main.py request.txt -hif headers.txt -hi "payload" -t 10
```

#### Payload File to Existing Headers
```bash
# Test multiple payloads on existing headers
python3 main.py request.txt -hipf payloads.txt -t 5 -s 1
```

### 2. Parameter Injection Testing

#### Single Parameter Injection
```bash
# Test single payload on all parameters
python3 main.py request.txt -pi "payload" -t 5
```

#### Payload File for Parameters
```bash
# Test multiple payloads on all parameters
python3 main.py request.txt -pif payloads.txt -t 10 -s 0.5
```

### 3. Path Traversal Testing
```bash
# Test path traversal with payload file
python3 main.py request.txt -pt traversal_payloads.txt -t 5 -s 1
```

### 4. HTTP Methods Testing
```bash
# Test dangerous HTTP methods
python3 main.py request.txt -m -t 5 -s 0.5
```

## 📁 File Formats

### Raw HTTP Request File
```
POST /api/test HTTP/1.1
Host: example.com
Content-Type: application/json
Authorization: Bearer token123
Cookie: session=abc123

{"id": 1, "name": "test"}
```

### Header Names File (`headers.txt`)
```
Accept
X-Forwarded-For
User-Agent
Referer
Authorization
Cookie
```

**Note**: Headers ending with `:` or `: ` will be automatically cleaned.

### Payload File (`payloads.txt`)
```
<script>alert(1);</script>
"><script>alert(1);</script>
javascript:alert(1)
'><script>alert(1);</script>
```

### Path Traversal Payloads (`traversal.txt`)
```
../etc/passwd
..\..\..\windows\system32\drivers\etc\hosts
....//....//....//etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

## 🎨 Output Examples

### Colored Status Codes
- 🟢 **Green**: 200-299 (Success)
- 🔵 **Cyan**: 300-399 (Redirect)
- 🟡 **Yellow**: 400-499 (Client Error)
- 🔴 **Red**: 500-599 (Server Error)

### Sample Output
```
[14:05:13] [INFO] ✉️ Header Injection Testing
[14:05:13] [INFO] 🔧 Using 5 thread(s)
[14:05:13] [INFO] Target URI: https://example.com/api/test
[14:05:13] [INFO] Payload Inject: <script>alert(1);</script>
[14:05:13] [INFO] 📊 Total headers to test: 15
[14:05:13] [INFO] Header 'Cookie: <script>alert(1);</script>' - Status Code: 200
[14:05:13] [INFO] Header 'Authorization: <script>alert(1);</script>' - Status Code: 401
[14:05:13] [INFO] ✅ Header injection testing completed
```

## ⚙️ Advanced Usage

### Combined Testing
```bash
# Multiple injection types with threading and filtering
python3 main.py request.txt \
  -hi "payload" \
  -pi "payload" \
  -pt traversal.txt \
  -m \
  -t 10 \
  -s 1 \
  -nr 3 \
  -sc "200,500" \
  -l INFO
```

### Stealth Testing
```bash
# Slow and stealthy testing
python3 main.py request.txt \
  -hipf payloads.txt \
  -t 1 \
  -s 2 \
  -nr 5 \
  -sc "4xx,5xx"
```

### Performance Testing
```bash
# Fast testing with multiple threads
python3 main.py request.txt \
  -pif payloads.txt \
  -t 20 \
  -s 0.1 \
  -sc "200"
```

### Comprehensive Security Testing
```bash
# Full security assessment
python3 main.py request.txt \
  -hif headers.txt -hi "XSS" \
  -pif payloads.txt \
  -pt traversal.txt \
  -m \
  -t 10 \
  -s 1 \
  -nr 5 \
  -sc "200,500" \
  -l INFO
```

## 🔧 Configuration

### Logging Levels
- `DEBUG`: Detailed debug information
- `INFO`: General information (default)
- `WARNING`: Warning messages
- `ERROR`: Error messages only
- `CRITICAL`: Critical errors only

### Status Code Filtering
```bash
# Specific codes
-sc "200,404,500"

# Range patterns
-sc "4xx,5xx"

# Mixed
-sc "200,4xx,500"
```

### Threading Guidelines
- **Low traffic**: 1-5 threads
- **Medium traffic**: 5-10 threads
- **High traffic**: 10-20 threads
- **Stealth mode**: 1 thread with sleep

### Sleep Recommendations
- **Stealth**: 1-3 seconds
- **Normal**: 0.5-1 second
- **Fast**: 0.1-0.5 seconds
- **Aggressive**: 0 seconds

## 📊 Performance Tips

### Optimization Strategies
1. **Start Small**: Begin with low thread count and increase gradually
2. **Monitor Responses**: Watch for rate limiting or server stress
3. **Use Sleep**: Implement delays to avoid detection
4. **Filter Results**: Use status code filtering to focus on relevant responses
5. **Retry Logic**: Configure retries for unstable connections

### Best Practices
- Test on authorized systems only
- Use appropriate sleep intervals
- Monitor server responses
- Document testing activities
- Stop if server shows signs of stress

## 🛡️ Security Considerations

### Responsible Usage
- **Authorized testing only**: Only test systems you own or have permission
- **Rate limiting**: Use sleep to avoid overwhelming servers
- **Legal compliance**: Follow local laws and regulations
- **Documentation**: Keep records of testing activities

### Best Practices
- Start with low thread count and increase gradually
- Use sleep to avoid detection
- Monitor server responses for rate limiting
- Stop testing if server shows signs of stress
- Respect robots.txt and terms of service

## 🐛 Troubleshooting

### Common Issues

#### Import Errors
```bash
# Install missing dependencies
pip install requests colorama beautifulsoup4 colorlog
```

#### File Not Found
```bash
# Check file paths
ls -la request.txt
ls -la payloads.txt
```

#### Permission Denied
```bash
# Check file permissions
chmod +r request.txt
chmod +r payloads.txt
```

#### Network Issues
```bash
# Test connectivity
curl -I https://target.com
```

#### Keyboard Interrupt
```bash
# Tool will gracefully exit with Ctrl+C
# No data corruption or incomplete states
```

## 📝 Examples

### Complete Testing Session
```bash
# 1. Create request file
cat > request.txt << 'EOF'
POST /api/user HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer token123

{"id": 1, "name": "test"}
EOF

# 2. Create payload file
cat > payloads.txt << 'EOF'
<script>alert(1);</script>
"><script>alert(1);</script>
javascript:alert(1)
EOF

# 3. Create header file
cat > headers.txt << 'EOF'
Accept
X-Forwarded-For
User-Agent
Referer
EOF

# 4. Run comprehensive test
python3 main.py request.txt \
  -hif headers.txt -hi "XSS" \
  -pif payloads.txt \
  -pt traversal.txt \
  -m \
  -t 5 \
  -s 1 \
  -nr 3 \
  -sc "200,500" \
  -l INFO
```

### Real-World Scenarios

#### Web Application Testing
```bash
# Test login form for injection vulnerabilities
python3 main.py login_request.txt \
  -pi "admin' OR '1'='1" \
  -pif sql_payloads.txt \
  -t 3 \
  -s 2 \
  -sc "200,302"
```

#### API Security Testing
```bash
# Test REST API endpoints
python3 main.py api_request.txt \
  -hi "XSS" \
  -pi "payload" \
  -m \
  -t 5 \
  -s 1 \
  -sc "200,400,500"
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any systems. The authors are not responsible for any misuse of this tool.

## 📞 Support

For issues, questions, or contributions:
- Create an issue on GitHub
- Check the documentation
- Review existing issues

---

**Happy Testing! 🎯**
