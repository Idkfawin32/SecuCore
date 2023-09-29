# SecuCore

## Disclaimer

**I created and use this library at my own risk, and you must fully evaluate any potential risks before implementing this in your own software. Any usage of this library is done at your own risk.**

## Overview

SecuCore is a customizable TCP Socket Library with TLS Support. It includes a custom async DNS resolver. This library is created for more discrete control over how secure connections are negotiated using .Net sockets.

## Features

### TCP Socket and Network Streams

- IPV4 connectivity (no IPV6 available)
- HTTP and SOCKS4/SOCKS5 proxy support natively (see the class definitions in "/Proxies")
- Cancellation after timeout
- Lightweight and scalable TCP connections with less resource usage compared to regular .Net implementations.

### HTTP Client

I created an HTTPClient object for usage and demonstration, but you can create other clients or tools using TCPSocket, TCPNetworkStream, and SecuredTCPStream. The HTTP client provides:

- Basic Cookie Support
- GET and POST requests
- TLS/SSL elevation when "https" is at the beginning of the URL.
- Chunked transfer encoding support
- Gzip support

### TLS Support

Although not very robust, the library provides support for TLS11 and TLS12 with three available cipher suites. It offers an option outside of "SslStream" for handling TLS, including key generation, encryption, verification, and signing. The available ciphersuites are:

- TLS_RSA_WITH_AES_128_CBC_SHA
- TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
- TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA

## Note

This library heavily relies on TPL and async/await, with many missing options for regular blocking calls.

## Simple Example: HTTP Get Request

```C#
string url = "https://www.google.com";
string refererurl = "https://www.amazon.com";
SecuCore.Clients.HTTPClient cl = new SecuCore.Clients.HTTPClient();
string response_body = await cl.GetAsync(url, refererurl).ConfigureAwait(false);
string response_headers = cl.LastHeaders;
```

## Conclusion

SecuCore is designed with an emphasis on avoiding application crashes and lockups, even when things do not behave as expected. Use it to enhance your control over TCP socket connections and TLS negotiations, all while benefiting from its lightweight and efficient design.
