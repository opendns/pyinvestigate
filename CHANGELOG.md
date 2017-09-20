# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [1.3.0] 2017-09-20
### Changed

All requests are now made via a 
[requests session](http://docs.python-requests.org/en/master/user/advanced/),
so the lib does not make new connections for each request. This should
significantly improve performance when doing lots of requests.
