# mod_auth_http - HTTP Authentication Module for ProFTPD

## Overview

`mod_auth_http` is a ProFTPD authentication module that validates user credentials by sending HTTP/HTTPS requests to an external authentication service. This allows ProFTPD to integrate with existing web-based authentication systems, REST APIs, or custom authentication services.

## Features

- **HTTP/HTTPS Support**: Authenticate against any HTTP or HTTPS endpoint
- **Flexible Configuration**: Support for POST and GET methods
- **Custom Headers**: Add API keys, authentication tokens, or custom headers
- **Response Parsing**: Extract user and group information from JSON responses
- **Caching**: Optional caching of successful authentications for performance
- **SSL/TLS**: Full SSL certificate verification support
- **Virtual Host Support**: Different authentication endpoints per virtual host

## Installation

### Prerequisites

- ProFTPD 1.3.x or later
- libcurl development libraries
- C compiler (gcc/clang)

### Building the Module

#### As a static module:

```bash
# Configure ProFTPD with mod_auth_http
./configure --with-modules=mod_auth_http:... \
            --with-includes=/usr/include/curl \
            --with-libraries=/usr/lib

make
make install
```

#### As a DSO (Dynamic Shared Object):

```bash
# Configure ProFTPD with DSO support
./configure --enable-dso --with-shared=mod_auth_http

# Build the module
cd contrib/
make mod_auth_http.so

# Install the module
make install-mod_auth_http
```

### Loading the Module

If built as a DSO, add to your proftpd.conf:

```apache
<IfModule mod_dso.c>
  LoadModule mod_auth_http.c
</IfModule>
```

## Configuration Directives

### AuthHTTPEngine
- **Syntax**: `AuthHTTPEngine on|off`
- **Default**: `off`
- **Context**: server config, `<VirtualHost>`, `<Global>`
- **Description**: Enable or disable HTTP authentication

### AuthHTTPURL
- **Syntax**: `AuthHTTPURL url`
- **Default**: none
- **Context**: server config, `<VirtualHost>`, `<Global>`
- **Description**: The URL of the authentication endpoint

### AuthHTTPTimeout
- **Syntax**: `AuthHTTPTimeout seconds`
- **Default**: `10`
- **Context**: server config, `<VirtualHost>`, `<Global>`
- **Description**: Timeout for HTTP requests in seconds

### AuthHTTPMethod
- **Syntax**: `AuthHTTPMethod POST|GET`
- **Default**: `POST`
- **Context**: server config, `<VirtualHost>`, `<Global>`
- **Description**: HTTP method to use for authentication requests

### AuthHTTPHeaders
- **Syntax**: `AuthHTTPHeaders "Header: Value"`
- **Default**: none
- **Context**: server config, `<VirtualHost>`, `<Global>`
- **Description**: Custom HTTP headers to include in requests

### AuthHTTPUserParam
- **Syntax**: `AuthHTTPUserParam param_name`
- **Default**: `username`
- **Context**: server config, `<VirtualHost>`, `<Global>`
- **Description**: Parameter name for the username

### AuthHTTPPasswordParam
- **Syntax**: `AuthHTTPPasswordParam param_name`
- **Default**: `password`
- **Context**: server config, `<VirtualHost>`, `<Global>`
- **Description**: Parameter name for the password

### AuthHTTPSuccessCode
- **Syntax**: `AuthHTTPSuccessCode code`
- **Default**: `200`
- **Context**: server config, `<VirtualHost>`, `<Global>`
- **Description**: HTTP status code indicating successful authentication

### AuthHTTPCacheTime
- **Syntax**: `AuthHTTPCacheTime seconds`
- **Default**: `0` (disabled)
- **Context**: server config, `<VirtualHost>`, `<Global>`
- **Description**: Time to cache successful authentications

### AuthHTTPSSLVerify
- **Syntax**: `AuthHTTPSSLVerify on|off`
- **Default**: `on`
- **Context**: server config, `<VirtualHost>`, `<Global>`
- **Description**: Enable SSL certificate verification

## Usage Examples

### Basic Configuration

```apache
<IfModule mod_auth_http.c>
  AuthHTTPEngine on
  AuthHTTPURL http://auth.example.com/authenticate
</IfModule>
```

### With Custom Headers and HTTPS

```apache
<IfModule mod_auth_http.c>
  AuthHTTPEngine on
  AuthHTTPURL https://api.example.com/v1/auth
  AuthHTTPHeaders "X-API-Key: secret123"
  AuthHTTPHeaders "Accept: application/json"
  AuthHTTPSSLVerify on
</IfModule>
```

### With Caching

```apache
<IfModule mod_auth_http.c>
  AuthHTTPEngine on
  AuthHTTPURL https://auth.example.com/validate
  AuthHTTPCacheTime 300  # Cache for 5 minutes
</IfModule>
```

## Authentication Endpoint Requirements

### Request Format

The module sends authentication requests in the following format:

#### POST Request
```http
POST /authenticate HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

username=john&password=secret123
```

#### GET Request
```http
GET /authenticate?username=john&password=secret123 HTTP/1.1
Host: auth.example.com
```

### Response Format

#### Simple Response
Return HTTP 200 for successful authentication, any other code for failure:

```http
HTTP/1.1 200 OK
```

#### JSON Response (Advanced)
Optionally return user/group information:

```json
{
  "authenticated": true,
  "user": {
    "uid": 1000,
    "gid": 1000,
    "home": "/home/john",
    "shell": "/bin/bash"
  },
  "groups": ["users", "developers", "ftp"]
}
```

## Security Considerations

1. **Always use HTTPS** in production to protect credentials in transit
2. **Enable SSL verification** (`AuthHTTPSSLVerify on`)
3. **Use strong API keys** when required by your authentication endpoint
4. **Implement rate limiting** on your authentication endpoint
5. **Monitor logs** for authentication failures and suspicious activity
6. **Use caching carefully** - balance security with performance

## Troubleshooting

### Enable Debug Logging

Add to proftpd.conf:

```apache
SystemLog /var/log/proftpd/proftpd.log
DebugLevel 5
```

### Common Issues

1. **Connection timeout**: Increase `AuthHTTPTimeout` or check network connectivity
2. **SSL errors**: Verify certificates or temporarily disable with `AuthHTTPSSLVerify off` (not for production!)
3. **Authentication failures**: Check HTTP response codes and endpoint logs
4. **Module not loading**: Ensure libcurl is installed and module is properly compiled

### Testing

Test authentication with curl:

```bash
# Test your endpoint directly
curl -X POST http://auth.example.com/authenticate \
     -d "username=testuser&password=testpass" \
     -H "X-API-Key: secret123"

# Test FTP connection
ftp localhost
> USER testuser
> PASS testpass
```

## Performance Tuning

- **Enable caching** for frequently authenticating users
- **Adjust timeout** based on your endpoint's response time
- **Use connection pooling** (implemented in the module)
- **Consider load balancing** multiple authentication endpoints

## Limitations

- Currently supports only basic authentication (username/password)
- JSON parsing is limited to simple structures
- No support for OAuth or token-based authentication (planned for future)

## Contributing

Contributions are welcome! Please submit pull requests or issues to the ProFTPD project.

## License

This module is distributed under the same terms as ProFTPD itself (GPL v2).

## Credits

Developed as part of the ProFTPD project. Based on the authentication framework of existing ProFTPD modules.