# Zaglushka

Simple python http server for API stubs.

For use only in dev or testing environments.

## Usage

`zaglushka.py --ports=8001,8002 --config=path/to/config.json`

If you want to bind ports <= 1024 use `sudo`.

See sample config definition [bellow](#use_cases).

## Requirements

* python 2.7 (python 3.2+ [in future releases](https://github.com/maizy/zaglushka/issues/17))
* tornado 3.2+ (with 4.0+ support)

## Installation

`pip install git+https://github.com/maizy/zaglushka.git`

or

```
git clone https://github.com/maizy/zaglushka.git
cd zaglushka
python setup.py install
```

## CI status

[![Travis CI, Build Status, master branch](https://travis-ci.org/maizy/zaglushka.svg?branch=master)](https://travis-ci.org/maizy/zaglushka)
[![Coveralls, Coverage Statusm master branch](https://img.shields.io/coveralls/maizy/zaglushka.svg)](https://coveralls.io/r/maizy/zaglushka?branch=master)


<a name="use_cases"/>
## Some use cases

### Simple error stub for any request url

```js
//config.json
{
    "urls": [
        {
            "path_regexp": ".*",
            "code": 500,
            "response": "<error>Pechal'ka exception: db connection error</error>",
            "headers" : {
                "Server": "MyBackendServer/0.5"
            }
        }
    ]
```

```bash
zaglushka.py --ports=5000,5001,5002 --config=config.json
```

```
curl -v http://127.0.0.1:5000/any_url
* Connected to 127.0.0.1 (127.0.0.1) port 5000 (#0)
> GET /any_url HTTP/1.1
> User-Agent: curl/7.37.1
> Host: 127.0.0.1:5000
> Accept: */*
>
< HTTP/1.1 500 Internal Server Error
< Content-Length: 55
* Server MyBackendServer/0.5 is not blacklisted
< Server: MyBackendServer/0.5
<
* Connection #0 to host 127.0.0.1 left intact
<error>Pechal'ka exception: db connection error</error>
```

Server watched for any changes in stub files or config and reload automatically.

### Emulate backend responses with `response_file` and `headers_file`

```js
//config.json
{
    "stubs_base_path": "./stubs",
    "urls": [
        {
            "path": "/some/page.html",
            "response_file": "page1.html",
            "headers_file": "page1.headers"
        }
    ]
```

### More complicated match rules

...

### Proxy all responses to real server, but stub someone with error

...


## Issues

* [issues for v0.1](https://github.com/maizy/zaglushka/issues?q=is%3Aopen+is%3Aissue+milestone%3A0.1)
* [post v0.1 issues](https://github.com/maizy/zaglushka/issues?q=is%3Aopen+is%3Aissue+no%3Amilestone)
* [submit you own ideas or bugs](https://github.com/maizy/zaglushka/issues/new)
