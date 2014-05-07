#!/usr/bin/env python
# _*_ coding: utf-8 _*_
import sys
import re
import logging
import json
import httplib
from os import path
from collections import namedtuple

from tornado.ioloop import IOLoop
from tornado.web import Application, RequestHandler, asynchronous, HTTPError
from tornado.options import define, options
from tornado.httpserver import HTTPServer

logger = logging.getLogger('zaglushka')

ResponseStub = namedtuple('ResponseStub', ['code', 'headers', 'body_func'])
Rule = namedtuple('Rule', ['matcher', 'responder'])


class Config(object):

    @classmethod
    def from_console_argument(cls, console_argument):
        # TODO: tests
        full_path = path.abspath(path.expanduser(console_argument))
        if not path.exists(full_path):
            logger.critical('Config not found at {}'.format(full_path))
            raise Exception('config not found')
        with open(full_path, 'rb') as config_fp:
            cleaned = json_minify(config_fp.read())
        try:
            raw = json.loads(cleaned, encoding='utf-8')
        except ValueError as e:
            logger.exception('Unable to parse config: {}'.format(e))
            raise
        return cls.from_config(raw, full_path)

    @classmethod
    def from_config(cls, raw, full_path):
        config_dirname = path.dirname(full_path)
        if 'stubs_base_path' in raw:
            raw_path = raw['stubs_base_path']
            if raw_path.startswith('/'):
                stubs_base_path = raw_path
            else:
                stubs_base_path = path.join(config_dirname, raw_path)
        else:
            stubs_base_path = config_dirname
        return cls(raw, path.abspath(stubs_base_path))

    def __init__(self, raw_config, stubs_base_path):
        self.raw = raw_config
        self.stubs_base_path = stubs_base_path
        rules = []
        for num, url_spec in enumerate(self.raw.get('urls', [])):
            matcher = choose_matcher(url_spec)
            if matcher is not None:
                responder = choose_responder(url_spec, stubs_base_path)
                if responder is None:
                    logger.warn('Unable to build responder from url spec #{}, skipping'.format(num))
                    continue
                else:
                    rules.append(Rule(matcher, responder))
            else:
                logger.warn('Unable to build matcher from url spec #{}, skipping'.format(num))
        rules.append(Rule(always_match, default_response))
        self.rules = rules


def choose_matcher(spec):
    method = spec['method'].upper() if 'method' in spec else None
    if 'path' in spec:
        return build_simple_matcher(spec['path'], method)
    elif 'path_regexp' in spec:
        return build_regexp_matcher(spec['path_regexp'], method, warn_func=logger.warning)
    else:
        return None


def build_simple_matcher(rel_path, method):
    return lambda request: (method is None or request.method == method) and request.path == rel_path


def build_regexp_matcher(pattern, method, warn_func=None):
    try:
        pattern_compiled = re.compile(pattern)
    except re.error as e:
        if warn_func is not None:
            warn_func('Unable to compile regexp "{}": {}'.format(pattern, e))
        return None
    return lambda request: ((method is None or request.method == method) and
                            re.search(pattern_compiled, request.path) is not None)

always_match = lambda _: True


def choose_responder(spec, base_stubs_path):
    code = int(spec.get('code', httplib.OK))
    headers = spec.get('headers', {})  # TODO: read from file
    if 'response' in spec:
        body = spec['response']
        if not isinstance(body, basestring):
            body = json.dumps(body, ensure_ascii=False, encoding=unicode)
        return build_static_response(body, headers, code)
    elif 'response_file' in spec:
        full_path = path.normpath(path.join(base_stubs_path, spec['response_file']))
        return build_file_response(full_path, headers, code)
    return None


def default_response():
    return ResponseStub(code=httplib.NOT_FOUND,
                        headers={
                            'X-Zaglushka-Default-Response': 'true',
                        },
                        body_func=lambda handler: handler.finish(''))


def build_static_response(body, headers=None, code=httplib.OK):

    def _static_responder():
        return ResponseStub(code=code,
                            headers=headers if headers is not None else {},
                            body_func=lambda handler: handler.finish(body))

    return _static_responder


def build_file_response(full_path, headers=None, code=httplib.OK):

    def _body_func(handler):
        # detect file at every request, so you can add it where ever you want
        if not path.isfile(full_path):
            logger.warning('Unable to find stubs file "{f}" for {m} {url}'
                           .format(f=full_path, m=handler.request.method, url=handler.request.uri))
            handler.set_header('X-Zaglushka-Failed-Response', 'true')
            return handler.finish('')
        send_file(handler.finish, full_path, handler)

    def _file_responder():
        return ResponseStub(code=code,
                            headers=headers if headers is not None else {},
                            body_func=_body_func)

    return _file_responder


def json_minify(data, strip_space=True):
    """
    json_minify v0.1 (C) Gerald Storer
    MIT License

    Based on JSON.minify.js:
    https://github.com/getify/JSON.minify
    """
    tokenizer = re.compile('"|(/\*)|(\*/)|(//)|\n|\r')
    in_string = False
    in_multiline_comment = False
    in_singleline_comment = False

    new_str = []
    from_index = 0  # from is a keyword in Python

    for match in re.finditer(tokenizer, data):

        if not in_multiline_comment and not in_singleline_comment:
            tmp2 = data[from_index:match.start()]
            if not in_string and strip_space:
                tmp2 = re.sub('[ \t\n\r]*', '', tmp2)  # replace only white space defined in standard
            new_str.append(tmp2)

        from_index = match.end()

        if match.group() == '"' and not in_multiline_comment and not in_singleline_comment:
            escaped = re.search('(\\\\)*$', data[:match.start()])
            if not in_string or escaped is None or len(escaped.group()) % 2 == 0:
                # start of string with ", or unescaped " character found to end string
                in_string = not in_string
            from_index -= 1  # include " character in next catch

        elif match.group() == '/*' and not in_string and not in_multiline_comment and not in_singleline_comment:
            in_multiline_comment = True
        elif match.group() == '*/' and not in_string and in_multiline_comment and not in_singleline_comment:
            in_multiline_comment = False
        elif match.group() == '//' and not in_string and not in_multiline_comment and not in_singleline_comment:
            in_singleline_comment = True
        elif ((match.group() == '\n' or match.group() == '\r') and not in_string and not in_multiline_comment and
                in_singleline_comment):
            in_singleline_comment = False
        elif (not in_multiline_comment and not in_singleline_comment and
              (match.group() not in ['\n', '\r', ' ', '\t'] or not strip_space)):
                new_str.append(match.group())

    new_str.append(data[from_index:])
    return ''.join(new_str)


def define_options():
    define('ports', multiple=True, type=int, help='listen ports (one or more)')
    define('config', type=str, help='zaglushka config path')


def send_file(cb, full_path, handler, chunk_size=1024 * 8, ioloop_=None):
    """
    :type handler: tornado.web.RequestHandler

    todo: async read (currently blocked, chunked output just a fiction)
    """
    ioloop_ = ioloop_ if ioloop_ is not None else IOLoop.current()
    fd = open(full_path, 'rb')

    def send_chunk():
        try:
            data = fd.read(chunk_size)
        except (IOError, OSError):
            data = None

        if data is not None and data != '':
            handler.write(data)
            ioloop_.add_timeout(0.1, handler.async_callback(send_chunk))
        else:
            fd.close()
            cb()

    send_chunk()


class StubHandler(RequestHandler):

    @asynchronous
    def get(self):
        self.send_stub()

    @asynchronous
    def post(self):
        self.send_stub()

    @asynchronous
    def put(self):
        self.send_stub()

    @asynchronous
    def delete(self):
        self.send_stub()

    @asynchronous
    def patch(self):
        self.send_stub()

    @asynchronous
    def head(self):
        self.send_stub()

    @asynchronous
    def options(self):
        self.send_stub()

    def send_stub(self):
        self.clear_header('Server')
        self.clear_header('Content-Type')
        self.clear_header('Date')
        config = self.application.settings['zaglushka_config']
        matched = False
        for rule in config.rules:
            if rule.matcher(self.request):
                responder = rule.responder()
                self.set_status(responder.code)
                for header, value in responder.headers.iteritems():
                    self.set_header(header, value)
                responder.body_func(self)
                matched = True
                break
        if not matched:
            raise HTTPError(httplib.INTERNAL_SERVER_ERROR)

    def compute_etag(self):
        return None


def build_app(zaglushka_config, debug=False):
    return Application(
        handlers=[(r'.*', StubHandler)],
        debug=debug,
        zaglushka_config=zaglushka_config
    )


def main(args):
    define_options()
    options.logging = 'debug'
    options.parse_command_line(args=args)
    if not options.config:
        logger.critical('--config param is requeired')
        return 1
    config = Config.from_console_argument(options.config)
    application = build_app(config, debug=True)
    server = HTTPServer(application)
    for port in options.ports:
        logger.info('Listen for 0.0.0.0:{}'.format(port))
        server.listen(port, '0.0.0.0')
    try:
        IOLoop.instance().start()
    except KeyboardInterrupt:
        logger.info('Server stopped')
        return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
