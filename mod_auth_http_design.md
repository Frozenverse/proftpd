# mod_auth_http - HTTP Authentication Module Design

## Overview
A ProFTPD authentication module that validates user credentials by sending HTTP POST requests to an external authentication service.

## Architecture

### Module Structure
- **Module Name**: `mod_auth_http`
- **Location**: `contrib/mod_auth_http/`
- **Main File**: `mod_auth_http.c`
- **Version**: `mod_auth_http/1.0`

### Core Components

#### 1. Configuration Directives
```
AuthHTTPEngine on|off                    # Enable/disable HTTP auth
AuthHTTPURL <url>                        # Authentication endpoint URL
AuthHTTPTimeout <seconds>                # Request timeout (default: 10)
AuthHTTPMethod POST|GET                  # HTTP method (default: POST)
AuthHTTPHeaders "Header: Value"           # Custom HTTP headers
AuthHTTPUserParam <param_name>           # Username parameter (default: "username")
AuthHTTPPasswordParam <param_name>       # Password parameter (default: "password")
AuthHTTPSuccessCode <code>               # Success HTTP status code (default: 200)
AuthHTTPUserField <json_field>           # JSON field for user data (optional)
AuthHTTPGroupField <json_field>          # JSON field for group data (optional)
AuthHTTPCacheTime <seconds>              # Cache successful auth (default: 0/disabled)
AuthHTTPSSLVerify on|off                 # SSL certificate verification (default: on)
```

#### 2. Authentication Flow
1. User connects and sends USER/PASS commands
2. Module intercepts authentication request
3. Creates HTTP request with credentials
4. Sends request to configured endpoint
5. Parses response to determine auth status
6. Optionally extracts user/group information from response
7. Returns authentication result

#### 3. HTTP Client Implementation

##### Option A: Using libcurl (Recommended)
**Pros:**
- Full-featured HTTP client
- SSL/TLS support built-in
- Handles redirects, cookies, etc.
- Well-tested and maintained

**Cons:**
- External dependency
- Larger footprint

##### Option B: Native socket implementation
**Pros:**
- No external dependencies
- Lighter weight
- Full control

**Cons:**
- Must implement HTTP protocol
- SSL/TLS would require OpenSSL
- More code to maintain

**Decision: Use libcurl for robust HTTP handling**

### Data Structures

```c
typedef struct {
    int engine;                    // Module enabled flag
    char *auth_url;               // Authentication endpoint
    int timeout;                  // Request timeout
    char *http_method;            // POST or GET
    array_header *headers;        // Custom headers
    char *user_param;             // Username parameter name
    char *pass_param;             // Password parameter name
    int success_code;             // Expected success HTTP status
    char *user_field;             // JSON field for user info
    char *group_field;            // JSON field for group info
    int cache_time;               // Auth cache duration
    int ssl_verify;               // SSL verification flag
    pool *pool;                   // Memory pool
} auth_http_config_t;

typedef struct {
    char *username;
    char *password;
    time_t cached_time;
    int cached_result;
    char *cached_groups;
} auth_http_cache_entry_t;
```

### Authentication Handlers

```c
// Main authentication handler
MODRET auth_http_auth(cmd_rec *cmd);

// Password verification
MODRET auth_http_chkpass(cmd_rec *cmd);

// User information handlers
MODRET auth_http_getpwnam(cmd_rec *cmd);
MODRET auth_http_getpwuid(cmd_rec *cmd);

// Group information handlers
MODRET auth_http_getgrnam(cmd_rec *cmd);
MODRET auth_http_getgrgid(cmd_rec *cmd);
MODRET auth_http_getgroups(cmd_rec *cmd);
```

### Request/Response Format

#### Request Format (POST)
```
POST /auth HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: XX

username=user&password=pass
```

#### Expected Response Formats

##### Simple (Status code only)
```
HTTP/1.1 200 OK
```

##### JSON Response (with user data)
```json
{
  "authenticated": true,
  "user": {
    "uid": 1000,
    "gid": 1000,
    "home": "/home/user",
    "shell": "/bin/bash"
  },
  "groups": ["users", "developers"]
}
```

## Implementation Plan

### Phase 1: Basic Module Structure
1. Create module skeleton with proper structure
2. Implement configuration directive handlers
3. Set up module initialization functions
4. Create basic authentication table

### Phase 2: HTTP Client Integration
1. Add libcurl detection to configure script
2. Implement HTTP POST request function
3. Add SSL/TLS support
4. Implement timeout handling
5. Add request/response logging

### Phase 3: Authentication Logic
1. Implement auth handler that intercepts USER/PASS
2. Build HTTP request with credentials
3. Parse HTTP response
4. Return authentication success/failure
5. Add optional JSON parsing for user data

### Phase 4: Caching & Performance
1. Implement authentication cache
2. Add cache expiration logic
3. Add connection pooling for HTTP requests
4. Implement retry logic for failed requests

### Phase 5: Advanced Features
1. Support for custom headers (API keys, etc.)
2. Support for different auth methods (Bearer tokens, etc.)
3. Group membership extraction from response
4. Virtual user support
5. Rate limiting support

### Phase 6: Testing & Documentation
1. Unit tests for HTTP client
2. Integration tests with mock HTTP server
3. Documentation and examples
4. Performance benchmarking

## File Structure

```
contrib/mod_auth_http/
├── mod_auth_http.c          # Main module implementation
├── mod_auth_http.h          # Header file
├── http_client.c            # HTTP client wrapper
├── http_client.h            # HTTP client header
├── json_parser.c            # Simple JSON parser (optional)
├── json_parser.h            # JSON parser header
├── Makefile.in              # Build configuration
├── mod_auth_http.html       # Documentation
└── t/                       # Test files
    ├── api/                 # Unit tests
    └── lib/                 # Test utilities
```

## Configuration Examples

### Basic Configuration
```apache
<IfModule mod_auth_http.c>
  AuthHTTPEngine on
  AuthHTTPURL http://auth.example.com/authenticate
  AuthHTTPTimeout 5
</IfModule>
```

### Advanced Configuration with JSON Response
```apache
<IfModule mod_auth_http.c>
  AuthHTTPEngine on
  AuthHTTPURL https://api.example.com/v1/auth
  AuthHTTPMethod POST
  AuthHTTPHeaders "X-API-Key: secret123"
  AuthHTTPHeaders "Accept: application/json"
  AuthHTTPSuccessCode 200
  AuthHTTPUserField "data.user"
  AuthHTTPGroupField "data.groups"
  AuthHTTPCacheTime 300
  AuthHTTPSSLVerify on
</IfModule>
```

## Security Considerations

1. **SSL/TLS**: Always use HTTPS for authentication requests
2. **Certificate Verification**: Verify SSL certificates by default
3. **Credential Protection**: Never log passwords in clear text
4. **Rate Limiting**: Implement rate limiting to prevent brute force
5. **Cache Security**: Cache should be memory-only, not persistent
6. **Input Validation**: Sanitize all user inputs before HTTP requests
7. **Timeout Handling**: Implement reasonable timeouts to prevent DoS

## Performance Considerations

1. **Connection Pooling**: Reuse HTTP connections where possible
2. **Caching**: Cache successful authentications for configurable period
3. **Async Operations**: Consider async HTTP requests for better performance
4. **Circuit Breaker**: Implement circuit breaker pattern for failing endpoints
5. **Load Balancing**: Support multiple authentication URLs

## Error Handling

1. **Network Failures**: Graceful fallback on connection errors
2. **Timeout Handling**: Configurable timeout with proper cleanup
3. **Invalid Responses**: Handle malformed HTTP/JSON responses
4. **Service Unavailable**: Option to fallback to other auth methods
5. **Logging**: Comprehensive logging at different debug levels

## Dependencies

### Required
- ProFTPD 1.3.x or later
- libcurl 7.x or later
- Standard C library

### Optional
- json-c or similar for JSON parsing
- OpenSSL for SSL/TLS (if not using curl's SSL)

## Build Instructions

```bash
# Configure ProFTPD with the HTTP auth module
./configure --with-modules=mod_auth_http --with-includes=/usr/include/curl --with-libraries=/usr/lib

# Or as a DSO module
./configure --enable-dso --with-shared=mod_auth_http

# Compile
make
make install
```

## Testing Strategy

### Unit Tests
- HTTP request building
- Response parsing
- Cache operations
- Configuration parsing

### Integration Tests
- Mock HTTP server for testing
- Various response formats
- Error conditions
- Performance testing

### Manual Testing
```bash
# Test with curl
curl -v ftp://user:pass@localhost/

# Test with ftp client
ftp localhost
> USER testuser
> PASS testpass
```

## Future Enhancements

1. **OAuth2 Support**: Add OAuth2 authentication flow
2. **JWT Support**: Support JWT token validation
3. **Webhook Support**: Send webhooks on auth events
4. **Multi-factor Auth**: Support for 2FA/MFA
5. **Session Management**: Extended session handling
6. **Metrics**: Prometheus/StatsD metrics export
7. **Circuit Breaker**: Advanced circuit breaker implementation
8. **Request Signing**: Support for signed requests (HMAC, etc.)