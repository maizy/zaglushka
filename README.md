# Zaglushka

Http server for stubing backends and emulate some errors.

For use only in dev or testing environments.

## Usage

`zaglushka.py [path/to/config.json] [port1,port2,...] [--other_options]`

If you want to bind ports <= 1024 use `sudo`.

### All options

* `zaglushka.py path/to/config.json` or `--config=path/to/config.json` – stubs config path.
  See sample config definition [bellow](#use_cases)

* `zaglushka.py config.json 5000,5001` or `--ports=5000,5001` – bind ports

* `--watch=false` – don't watch config and stubs for changes (true by default).

* `--help` – display help for all available options.

## Requirements

* python 3.5+
* tornado 5.1 - 6

## Installation

`pip install zaglushka` (recommended)

or

`pip install git+https://github.com/maizy/zaglushka.git`

or

```
git clone https://github.com/maizy/zaglushka.git
cd zaglushka
python setup.py install
```

## CI status

[![codecov](https://codecov.io/gh/maizy/zaglushka/branch/master/graph/badge.svg)](https://codecov.io/gh/maizy/zaglushka)

<a name="use_cases"></a>

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
}
```

```bash
zaglushka.py config.json 5000
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
    "stubs_base_path": "./stubs",  //by default dirname of config.json used
    "urls": [
        {
            "path": "/some/page.html",
            "response_file": "page1.html",
            "headers_file": "page1.headers"
        }
    ]
}
```

### More complicated match rules

```js
{
    "urls": [
        {
            "path": "/users/maizy/repos",
            "response_file": "stubs/page1.json",
            "headers_file": "stubs/page1.headers",
            "query": {
                "required": {
                    "page": "1",
                    "per_page": "100"
                },
                "other_allowed": true  // also match if any additional param exists
            }
        },

        {
            "path": "/users",
            "response_code": 404,
            "response": "not found",
            "query": {
                "required": {
                    "user_id": "117",
                    "field": ["name", "email"]  // multiple param value
                },
                "other_allowed": false  // strict match
            }
        }
    ]
}
```

### Proxy responses to real server, but stub some with error

```js
{
    "urls": [
        {
            "path": "/user/m/maizy",
            "response": "forbidden",
            "response_code": 403
        },
        {
            "path_regexp": "^/user/(\\w+)/(.*)$",
            "response_proxy": "http://example.com/app/users/$1/$2" // $1, $2 ... - reg exp matches
        }
    ]
}
```


## Issues

* [issues](https://github.com/maizy/zaglushka/issues?q=is%3Aopen+is%3Aissue+no%3Amilestone)
* [submit you own ideas or bugs](https://github.com/maizy/zaglushka/issues/new)


## Build release

* update version in `setup.py`
* add git tag
* setup ~/.pypirc
* `python setup.py sdist`
* `twine upload dist/*`
