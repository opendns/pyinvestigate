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

## [1.4.0] 2018-04-17
### Changed

Make library compatible with both python 2.x and python 3.x. 

## [1.5.0] 2018-08-24
### Changed

Added timeline endpoint to library, cleaned up deprecated endpoints. 
