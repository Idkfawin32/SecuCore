# SecuCore

DISCLAIMER: I created and use this library at my own risk and you must fully evaluate any risk potentials before implementing this in your own software. Any usage of this library is done at your own risk. 
While efforts have been made to ensure the security and reliability of this library, it is important to acknowledge that no system can be completely secure. 
You are advised to be cautious and aware of the potential security risks involved in using this library, and to take appropriate measures to mitigate these risks.

Customizable TCP Socket Library with TLS Support. A custom async DNS resolver is also provided. I wanted to have more discrete control over how Secure connections are negotiated using .Net sockets.

The TCP Socket and Network Streams provide:
-IPV4 connectivity(no IPV6 available)
-HTTP and SOCKS4/SOCKS5 proxy support(natively, see the class definitions in "/Proxies"
-Cancellation after timeout, actually returns/doesn't lock up
-Lightweight and Scalable TCP connections, GC doesn't get called as often and there is overall less resource usage when compared to the regular .Net HTTPWebRequest and NetworkStream implementations.

I created an HTTPClient object for usage and demonstration of this library, but by using TCPSocket, TCPNetworkStream, and SecuredTCPStream you can make other clients or tools.

The http client provides:
-Basic Cookie Support
-Get Requests
-Post Requests
-TLS/SSL elevation when "https" is at the begining of the url.

NOTE: This library heavily relies on TPL and async/await, there are many missing options for regular blocking calls.

The TLS portion of the library provides:
-An option outside of "SslStream", the reason I made this library
-Key Generation/Encryption/Verification/Signing

Support for TLS is not VERY robust, I have implemented TLS11 and TLS12, however there are only three cipherSuites available:
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA

My approach to handling TLS is a bit psychotic, but it was designed in such a way that Application Crashes and lockups are avoided when things do not behave as they should.



# Simple Example HTTP Get Request
```C#
string url = "https://www.google.com";
string refererurl = "https://www.amazon.com";
SecuCore.Clients.HTTPClient cl = new SecuCore.Clients.HTTPClient();
string response_body = await cl.GetAsync(url, refererurl).ConfigureAwait(false);
string response_headers = cl.LastHeaders;
