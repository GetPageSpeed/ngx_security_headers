# Changelog
All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-02-03
### Added
* Cross-Origin-Resource-Policy (CORP) header support via `security_headers_corp` directive (default: `same-site`)
* Cross-Origin-Opener-Policy (COOP) header support via `security_headers_coop` directive (default: `omit`)
* Cross-Origin-Embedder-Policy (COEP) header support via `security_headers_coep` directive (default: `omit`)
* COEP `credentialless` value for more flexible cross-origin isolation

Fixes #17

## [0.1.0] - 2023-09-06
#### Fixed
* HSTS set to 1 year instead of 2 years by default (#18)
* New default `X-XSS-Protection: 0`, see #19

## [0.0.11] - 2022-03-18
#### Fixed
* Sending HSTS header no longer requires building with OpenSSL #12
* Fixes HSTS preload was not added by default #15

## [0.0.10] - 2022-03-13
#### Added
* Ability to opt-out of added `preload` addition for HSTS, using `security_headers_hsts_preload off;`.
* Remove X-Application-Version header
* For adding HSTS, check URL protocol instead of connection protocol to be 'https://' #12

## [0.0.9] - 2020-05-31
### Changed
* `X-Content-Type-Options` is now sent for all resources to accomodate Chromium's CORB 
(see [webhint.io #1221](https://github.com/webhintio/hint/issues/1221)) 

