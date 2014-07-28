# Zaglushka

Simple python http server for API stubs.

For use only in dev or testing environments.

## Usage

`zaglushka.py --ports=8001,8002 --config=path/to/config.json`

If you want to bind ports <= 1024 use `sudo`.

See sample config definition at [examples/example.json](examples/example.json)

## Requirements

* python 2.7
* tornado 3.2+

## Installation

`pip install git+https://github.com/maizy/zaglushka.git`

or

```
git clone https://github.com/maizy/zaglushka.git
cd zaglushka
python setup.py install
```

## Test status

![master branch](https://travis-ci.org/maizy/zaglushka.svg?branch=master)
