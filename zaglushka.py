#!/usr/bin/env python
# _*_ coding: utf-8 _*_
import sys
import re
import logging
import json
import httplib
import time
from os import path
from collections import namedtuple

from tornado.ioloop import IOLoop
from tornado.web import Application, RequestHandler, asynchronous, HTTPError
from tornado.options import define, options
from tornado.httpserver import HTTPServer
from tornado.httputil import HTTPHeaders

logger = logging.getLogger('zaglushka')


class ResponseStub(namedtuple('_ResponseStub', ['code', 'headers_func', 'body_func', 'delay'])):
    def __new__(cls, **kwargs):
        data = {k: None for k in cls._fields}
        data.update(kwargs)
        return super(ResponseStub, cls).__new__(cls, **data)


Rule = namedtuple('Rule', ['matcher', 'responder'])


def _get_stub_file_path(base_stubs_path, stub_path):
    return stub_path if stub_path.startswith('/') else path.join(base_stubs_path, stub_path)


class Config(object):

    @classmethod
    def from_console_argument(cls, config_full_path):
        # TODO: tests
        if not path.exists(config_full_path):
            logger.error('Config not found at {}'.format(config_full_path))
            raise Exception('config not found')
        with open(config_full_path, 'rb') as config_fp:
            cleaned = json_minify(config_fp.read())
        try:
            raw_config = json.loads(cleaned, encoding='utf-8')
        except ValueError as e:
            logger.error('Unable to parse config: {}'.format(e))
            raise
        return cls(raw_config, config_full_path)

    def __init__(self, raw_config, config_full_path):
        self.watched_files = {config_full_path}
        config_dirname = path.dirname(config_full_path)
        if 'stubs_base_path' in raw_config:
            stubs_base_path = _get_stub_file_path(config_dirname, raw_config['stubs_base_path'])
        else:
            stubs_base_path = config_dirname
        stubs_base_path = path.abspath(stubs_base_path)
        self.raw = raw_config
        rules = []
        for num, url_spec in enumerate(self.raw.get('urls', [])):
            matcher = choose_matcher(url_spec)
            if matcher is not None:
                responder, responder_paths = choose_responder(url_spec, stubs_base_path)
                self.watched_files.update(responder_paths)
                rules.append(Rule(matcher, responder))
            else:
                logger.warn('Unable to build matcher from url spec #{}, skipping'.format(num))
        default_response = static_response(
            body='',
            headers_func=build_static_headers_func({
                'X-Zaglushka-Default-Response': 'true',
            }),
            code=httplib.NOT_FOUND
        )
        rules.append(Rule(always_match, default_response))
        self.rules = rules
        self.stubs_base_path = stubs_base_path


def choose_matcher(spec):
    method = spec['method'].upper() if 'method' in spec else None
    if 'query' in spec:
        query_args_matcher = build_simple_query_args_matcher(spec['query'])
    else:
        query_args_matcher = always_match

    if 'path' in spec:
        return build_simple_matcher(spec['path'], method, query_args_matcher)
    elif 'path_regexp' in spec:
        return build_regexp_matcher(spec['path_regexp'], method, query_args_matcher, warn_func=logger.warning)
    else:
        return None


def _is_args_matched(real_args, required, other_allowed=True):
    def _spec2list(dict_):
        res = []
        for arg, val in dict_.iteritems():
            if isinstance(val, (list, set, tuple)):
                res.extend((unicode(arg), unicode(v)) for v in val)
            else:
                res.append((unicode(arg), unicode(val)))
        return res

    required = _spec2list(required)
    real = _spec2list(real_args)
    matched = []

    if not other_allowed and len(real) > 0 and len(required) == 0:
        return False

    for pair in real:
        try:
            match_index = required.index(pair)
        except ValueError:
            match_index = None
        if match_index is None and not other_allowed:
            return False
        elif match_index is not None:
            required.pop(match_index)
            matched.append(pair)

    return len(required) == 0


def build_simple_query_args_matcher(args_spec):

    def _simple_query_args_matcher(request):
        return _is_args_matched(request.arguments, args_spec.get('required', {}), args_spec.get('other_allowed', True))

    return _simple_query_args_matcher


def build_simple_matcher(rel_path, method, query_args_matcher):
    return lambda request: ((method is None or request.method == method) and request.path == rel_path and
                            query_args_matcher(request))


def build_regexp_matcher(pattern, method, query_args_matcher, warn_func=None):
    try:
        pattern_compiled = re.compile(pattern)
    except re.error as e:
        if warn_func is not None:
            warn_func('Unable to compile regexp "{}": {}'.format(pattern, e))
        return None
    return lambda request: ((method is None or request.method == method) and
                            re.search(pattern_compiled, request.path) is not None and
                            query_args_matcher(request))


def always_match(*_, **__):
    return True


def choose_responder(spec, base_stubs_path):
    code = int(spec.get('code', httplib.OK))
    delay = float(spec['delay']) if 'delay' in spec else None
    stub_kwargs = {'code': code, 'delay': delay}
    headers_func, paths = choose_headers_func(spec, base_stubs_path)
    if 'response' in spec:
        body = spec['response']
        if not isinstance(body, basestring):
            body = json.dumps(body, ensure_ascii=False, encoding=unicode)
        return static_response(body, headers_func, **stub_kwargs), paths
    elif 'response_file' in spec:
        full_path = path.normpath(path.join(base_stubs_path, spec['response_file']))
        paths.add(full_path)
        return filebased_response(full_path, headers_func, warn_func=logger.warning, **stub_kwargs), paths
    else:
        return static_response(b'', headers_func, **stub_kwargs), paths


def static_response(body, headers_func, **stub_kwargs):

    def _body_func(handler, ready_cb):
        handler.write(body)
        ready_cb()

    return ResponseStub(headers_func=headers_func,
                        body_func=_body_func,
                        **stub_kwargs)


def filebased_response(full_path, headers_func, warn_func=None, **stub_kwargs):

    def _body_func(handler, ready_cb):
        # detect file at every request, so you can add it where ever you want
        if not path.isfile(full_path):
            if warn_func is not None:
                warn_func('Unable to find stubs file "{f}" for {m} {url}'
                          .format(f=full_path, m=handler.request.method, url=handler.request.uri))
            handler.set_header('X-Zaglushka-Failed-Response', 'true')
            return ready_cb()
        send_file(ready_cb, full_path, handler)

    return ResponseStub(headers_func=headers_func,
                        body_func=_body_func,
                        **stub_kwargs)


def choose_headers_func(spec, base_stubs_path):
    paths = set()
    if 'headers' in spec:
        return build_static_headers_func(spec['headers']), paths
    elif 'headers_file' in spec:
        stub_path = _get_stub_file_path(base_stubs_path, spec['headers_file'])
        paths.add(stub_path)
        return build_filebased_headers_func(stub_path, warn_func=logger.warning), paths
    else:
        return build_static_headers_func({}), paths


def build_static_headers_func(headers):

    def _static_headers_func(handler):
        for header, values in headers.iteritems():
            if not isinstance(values, (list, tuple, set, frozenset)):
                values = [values]
            for value in values:
                handler.add_header(header, value)

    return _static_headers_func


def build_filebased_headers_func(full_path, warn_func=None):

    def _filebased_headers_func(handler):
        if not path.isfile(full_path):
            if warn_func is not None:
                warn_func('Unable to find headers stubs file "{f}" for {m} {url}'
                          .format(f=full_path, m=handler.request.method, url=handler.request.uri))
            handler.add_header('X-Zaglushka-Failed-Headers', 'true')
            return
        for header, value in HTTPHeaders.parse(open(full_path, 'r').read()).get_all():
            handler.add_header(header, value)

    return _filebased_headers_func


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
    define('ports', multiple=True, type=int, help='listen ports (one or more)', metavar='PORT[,PORT,...]',
           default=[8001])
    define('config', type=str, help='zaglushka config path')
    define('watch', type=bool, help='watch config and stubs for changes', default=True)


def send_file(cb, full_path, handler, chunk_size=1024 * 8, ioloop_=None):
    """
    :type handler: tornado.web.RequestHandler

    todo: async read (currently blocked, chunked output just a fiction)
    """
    ioloop_ = ioloop_ if ioloop_ is not None else IOLoop.current()
    fd = open(full_path, 'rb')  # TODO: check exceptions

    def send_chunk():
        try:
            data = fd.read(chunk_size)
        except (IOError, OSError):
            data = None

        if data is not None and data != '':
            handler.write(data)
            ioloop_.add_timeout(0.1, send_chunk)
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

    def _make_response_with_rule(self, responder):
        """
        :type responder: ResponseStub
        """
        ioloop = IOLoop.current()
        if responder.delay is None:
            finish_cb = self.finish
        else:
            def finish_cb():
                timeout = time.time() + responder.delay
                logger.debug('Delay response for {m} {u} by {sec:.3f} sec'.format(m=self.request.method,
                                                                                  u=self.request.uri,
                                                                                  sec=responder.delay))
                ioloop.add_timeout(timeout, self.finish)

        self.set_status(responder.code)
        responder.headers_func(self)
        responder.body_func(self, finish_cb)

    def send_stub(self):
        self.clear_header('Server')
        self.clear_header('Content-Type')
        self.clear_header('Date')
        config = self.application.settings['zaglushka_config']
        matched = False
        for rule in config.rules:
            if rule.matcher(self.request):
                self._make_response_with_rule(rule.responder)
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


def wait_when_config_fixed(config_full_path, exception=None):
    import tornado.autoreload
    logger.error('Your config in broken. Fix it then server starts automaticaly.')
    logger.error('Config error: {}'.format(exception))
    logger.error('Server not started')
    tornado.autoreload.watch(config_full_path)
    tornado.autoreload.wait()


def main(args):
    define_options()
    options.logging = 'debug'
    options.parse_command_line(args=args)
    watch = options.watch
    config_full_path = path.abspath(path.expanduser(options.config))
    if not options.config:
        logger.error('--config param is required')
        return 1
    try:
        config = Config.from_console_argument(config_full_path)
    except Exception as e:
        return wait_when_config_fixed(config_full_path, e) if watch else 2
    application = build_app(config, debug=True)
    if watch:
        import tornado.autoreload
        map(tornado.autoreload.watch, config.watched_files)
    server = HTTPServer(application)
    logger.info('Server started')
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
