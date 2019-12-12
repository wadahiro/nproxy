# nproxy

**nproxy** is a spceial proxy server for conneting between your PC and upstream proxy server in you organization.

There are some unique features.

- Inject Proxy-Authorization header from standard environment variables, `http_proxy` and `https_proxy`.
- Generate self-signed server certificate dynamically to support Apple's [Requirements for trusted certificates in iOS 13 and macOS 10.15](https://support.apple.com/en-us/HT210176) if the server certificate is invalid.
- Support reading pac file for using upstream proxy.
