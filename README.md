## KatWebX
An extremely fast static web-server and reverse proxy for the modern web.

## Important Info 
KatWebX is a work in progress, and you will likely encounter bugs. **KatWebX is not well tested, production use is not recommended!**  If you need something which will is well tested and can be used in production, check out [KatWeb](https://github.com/kittyhacker101/KatWeb) instead.

## Release Schedule
Approximate dates for the release of KatWebX (and discontinuing of KatWeb) are listed below.
 - Around December 2018 - KatWebX becomes feature complete, and begins testing in some production environments. 
 - December 16, 2018 - KatWebX's first beta release.
 - January 12, 2019 - KatWebX's first pre-release. During the time from pre-release to release, no new features will be added, and the configuration format will not be changed.
 - Febuary 3, 2019 - KatWebX's first release.
 - Febuary 17, 2019 - A tool is released to automatically migrate configuration from KatWeb to KatWebX. 
 - March 2, 2019 - All KatWeb users will be told to upgrade to KatWebX.
 - June 13, 2019 - KatWeb is given EOL status, and is discontinued. 

## Current/Planned Features
- [x] Flexible config parsing
- [x] Server-side redirects
- [x] Regex-based redirects
- [x] Flexible config parsing
- [x] Compressed reverse proxy
- [x] Websocket reverse proxy
- [x] Regex-based reverse proxying
- [x] Automatic proxy compression
- [x] HTTP basic authentication
- [x] Regex-based auth
- [x] Fast file serving
- [x] Brotli file compression
- [x] HSTS support
- [x] HTTP/2 and HTTP/1.1 support
- [x] High peformance TLS 1.3
- [x] SNI support
- [ ] OCSP stapling support
- [x] Advanced logging support
- [x] Material design error pages
- [x] Material design file listing

## Possible Features
- On-the-fly config reloading
- QUIC support
- Let's Encrypt integration
- Caching proxy
- Advanced load balancer
