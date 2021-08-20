# bumpkey

A PKCS #11 module written in Rust for exposing client certificates to applications that lack native integration with platform certificate stores.

This is not an officially supported Google product

## Functionality

bumpkey only implements the subset of the PKCS#11 interface that is required for supporting client certificates with these platforms and applications.

### Platforms

*   macOS
*   Windows

### Applications

*   Google Chrome
*   Firefox (NSS)
*   p11-kit
*   OpenVPN