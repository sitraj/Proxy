# Secret Detection Plugin

This plugin for the SSL Proxy detects potential sensitive information in HTTP/HTTPS traffic.

## Features

- Detects various types of sensitive information:
  - API keys
  - AWS credentials
  - Passwords
  - JWT tokens
  - Private keys
  - Credit card numbers
  - Email addresses
  - IP addresses
  - Social Security Numbers
  - Phone numbers

- Saves findings to JSON files in the `results/secrets` directory
- Includes context around detected secrets
- Timestamps all findings

## How It Works

The plugin scans both request and response bodies and headers for patterns that match common sensitive information formats. When a potential secret is found, it's saved to a JSON file with:

- Timestamp
- Type of secret
- The detected value
- Context (surrounding text)
- Source (which request/response it was found in)

## Usage

1. The plugin is automatically loaded by the proxy server
2. No configuration is needed
3. Results are saved to `results/secrets/secrets_YYYYMMDD_HHMMSS.json`

## Customization

You can modify the `PATTERNS` dictionary in `__init__.py` to add or remove patterns to detect.

## Example Output

```json
[
  {
    "timestamp": "20230406_123045",
    "type": "api_key",
    "value": "abcdef1234567890abcdef1234567890",
    "context": "...\"api_key\": \"abcdef1234567890abcdef1234567890\",...",
    "source": "Request: https://api.example.com/data"
  }
]
``` 