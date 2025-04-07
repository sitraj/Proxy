# SSL Proxy

A Python-based SSL proxy server that can intercept and analyze HTTP/HTTPS traffic. This tool is useful for debugging, security testing, and analyzing web traffic.

## Features

- HTTP/HTTPS traffic interception
- SSL certificate generation for HTTPS interception
- XSS (Cross-Site Scripting) detection
- Secret detection (API keys, passwords, tokens, etc.)
- Input field analysis
- Request/Response header logging
- Content encoding/decoding support (gzip, deflate)
- Plugin system for extensibility

## Requirements

- Python 3.x
- OpenSSL (for certificate generation)
- Required Python packages (install using `pip`):
  ```
  pip install -r requirements.txt
  ```

## Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/sitraj/Proxy.git
   cd Proxy
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Generate SSL certificates:
   - Generate a CA key:
     ```bash
     openssl genrsa -out ca.key 2048
     ```
   - Generate a CA certificate:
     ```bash
     openssl req -new -x509 -days 3650 -key ca.key -out ca.crt
     ```
   - Generate a certificate key for the proxy:
     ```bash
     openssl genrsa -out cert.key 2048
     ```

4. Create necessary directories:
   ```bash
   mkdir certs
   mkdir results
   ```

## Usage

1. Start the proxy server:
   ```bash
   python3 sslproxy.py
   ```
   The proxy server will start on `localhost:8081`

2. Configure your browser/system to use the proxy:
   - Proxy Address: `localhost` or `127.0.0.1`
   - Port: `8081`

3. For HTTPS interception:
   - Import `ca.crt` into your browser/system's trusted root certificates
   - Different systems/browsers have different methods for importing certificates

## Project Structure

- `sslproxy.py`: Main proxy server script
- `classes/`
  - `proxyrequesthandler.py`: Core proxy request handling logic
  - `httpserverclass.py`: HTTP server implementation
  - `stringhandler.py`: Content encoding/decoding utilities
- `plugins/`
  - `xssfind/`: XSS detection plugin
  - `ReqHandle/`: Request handling plugin
  - `secretdetect/`: Secret detection plugin
- `certs/`: Directory for generated SSL certificates
- `results/`: Directory for analysis results

## Plugin System

The proxy server supports plugins for extending functionality. Plugins should be placed in the `plugins/` directory and follow the plugin interface defined in the project.

### Built-in Plugins

#### XSS Detection
Scans for potential Cross-Site Scripting vulnerabilities in web applications.

#### Secret Detection
Identifies sensitive information such as API keys, passwords, tokens, and personal data in HTTP/HTTPS traffic.

#### Request Handler
Allows modification of requests before they are sent to the target server.

## Security Notes

- This tool is for educational and debugging purposes only
- Be cautious when using it on production systems
- Always handle SSL certificates securely
- Be aware of local security and privacy regulations when intercepting traffic
- Be careful with detected secrets - ensure they are handled securely

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.




