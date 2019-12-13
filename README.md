# nproxy

**nproxy** is a spceial proxy server for conneting between your PC and upstream proxy server in you organization.

There are some unique features.

- Inject Proxy-Authorization header from standard environment variables, `http_proxy` and `https_proxy`.
- Generate self-signed server certificate dynamically to support Apple's [Requirements for trusted certificates in iOS 13 and macOS 10.15](https://support.apple.com/en-us/HT210176) if the server certificate is invalid.
- Support reading pac file to find upstream proxy.


# Install

You can download the binary from [release page](https://github.com/wadahiro/nproxy).


# Usage

```
nproxy.

Usage:

  main [options]

Options:

  -b string
        Bind address and port (default ":3128")
  -ca-cert string
        CA cert file (PEM)
  -ca-key string
        CA private key file (PEM)
  -enable-dump
        Enable request/response dump
  -gen-ca
        Generate own CA certificate and private key
  -insecure
        Skip certificate verification when connecting to upstream (Don't use!)
  -log-level string
        Log level, one of: debug, info, warn, error, panic (default "info")
  -pac string
        PAC URL
exit status 2
```

## Basic

Set the upstream proxy as environment variables `http_proxy` and `https_proxy`.
Then run `ngproxy`. It starts a proxy server on `:3128`.

```
export http_proxy=http://upstream-proxy.example.org:4000
export https_proxy=http://upstream-proxy.example.org:4000
nproxy
[  info ] 2019/12/13 00:01:44.517383 No pac URL and environment variable. The proxy uses standard environment variables for upstream proxy.
[  info ] 2019/12/13 00:01:44.517628 Starting NPROXY: :3128
```

If your organization provides pac file, you can use it using `pac` option.

```
nproxy -pac http://example.org/pacfile
```

If the upstream proxy requires authentication, set the username and credential as environment variables. Then run `nproxy`.
`Proxy-Authorization` header is injected automatically.

```
export http_proxy=http://foo:bar@upstream-proxy.example.org:4000
export https_proxy=http://foo:bar@upstream-proxy.example.org:4000
nproxy
[  info ] 2019/12/13 00:06:27.140236 No pac URL. The proxy uses standard environment variables for upstream proxy.
[  info ] 2019/12/13 00:06:27.140486 Detected userInfo for HTTP proxy in environment variables. The userInfo is used as Proxy Authorization for the upstream proxy.
[  info ] 2019/12/13 00:06:27.140511 Detected userInfo for HTTPS proxy in environment variables. The userInfo is used as Proxy Authorization for the upstream proxy.
[  info ] 2019/12/13 00:06:27.140762 Starting NPROXY: :3128
```

You can use `pac` option too.

```
export http_proxy=http://foo:bar@upstream-proxy.example.org:4000
export https_proxy=http://foo:bar@upstream-proxy.example.org:4000
nproxy -pac http://example.org/pacfile 
[  info ] 2019/12/13 00:56:53.640443 Detected userInfo for HTTP proxy in environment variables. The userInfo is used as Proxy Authorization for the upstream proxy.
[  info ] 2019/12/13 00:56:53.640746 Detected userInfo for HTTPS proxy in environment variables. The userInfo is used as Proxy Authorization for the upstream proxy.
[  info ] 2019/12/13 00:56:53.682394 Got pac file from http://nrigallweb.wwws.nri.co.jp/proxyconf/cubeconf.pac
[  info ] 2019/12/13 00:56:53.682758 Starting NPROXY: :3128
```

Also, you can this proxy without upstream proxy server. Run `nproxy` without environment variable.

```
nproxy
[  info ] 2019/12/13 00:01:44.517383 No pac URL and environment variable. The proxy doesn't use upstream proxy.
[  info ] 2019/12/13 00:01:44.517628 Starting NPROXY: :3128
```


## How to use self-singnd server ceritification 

First, create your own CA. `nproxy` can generate it using `gen-ca` option.
Or you can generate it using `openssl` command, etc.

```
nproxy -gen-ca
```

Now you can see `ca.crt` and `ca.key` files in the current directory.

Then **you need to import `ca.crt` file into you PC as a trusted certificate**.
Finally, run `nproxy` using `ca-cert` and `ca-key` options. You need to specify the generated files. 

```
nproxy -ca-cert ca.crt -ca-key ca.key ...(other options)
```


# License

Licensed under the [MIT](/LICENSE).
