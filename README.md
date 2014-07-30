# Zaglushka

Simple python http server for API stubs.

For use only in dev or testing environments.

## Usage

`zaglushka.py --ports=8001,8002 --config=path/to/config.json`

If you want to bind ports <= 1024 use `sudo`.

See sample config definition at [examples/example.json](examples/example.json) and
[some more useful examples](examples/).

## Requirements

* python 2.7 (python 3.2+ [in future releases](https://github.com/maizy/zaglushka/issues/17))
* tornado 3.2+ (currenly <4.0, [will be fixed](https://github.com/maizy/zaglushka/issues/16))

## Installation

`pip install git+https://github.com/maizy/zaglushka.git`

or

```
git clone https://github.com/maizy/zaglushka.git
cd zaglushka
python setup.py install
```

## CI status

![Travic CI, test passed: master branch](https://travis-ci.org/maizy/zaglushka.svg?branch=master)

[![Coveralls, coverage status: master branch](https://img.shields.io/coveralls/maizy/zaglushka.svg)](https://coveralls.io/r/maizy/zaglushka?branch=master)


## Issues

* [issues for v0.1](https://github.com/maizy/zaglushka/issues?q=is%3Aopen+is%3Aissue+milestone%3A0.1)
* [post v0.1 issues](https://github.com/maizy/zaglushka/issues?q=is%3Aopen+is%3Aissue+no%3Amilestone)
* [submit you own ideas or bugs](https://github.com/maizy/zaglushka/issues/new)
