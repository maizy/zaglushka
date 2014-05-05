# Zaglushka

Simple python http server for API stubs.

For use only in dev or testing environments.

## Usage

`zaglushka.py --ports=8001,8002 --config path/to/config.json`

If you want to bind ports <= 1024 use `sudo`.

See sample config defenition at [examples/example.json](examples/example.json)

## Requirements

* python 2.7
* tornado 3.2+
