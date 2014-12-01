# _*_ coding: utf-8 _*_
import time
import httplib
from os import path
import socket
from StringIO import StringIO
from functools import partial

from tornado.httpclient import HTTPResponse

import zaglushka
from zaglushka_tests import ZaglushkaAsyncHTTPTestCase, TEST_RESOURCES_DIR


class ProxiedResponseTestCase(ZaglushkaAsyncHTTPTestCase):

    def __init__(self, *args, **kwargs):
        super(ProxiedResponseTestCase, self).__init__(*args, **kwargs)
        self._orig_fetch = zaglushka._fetch_request

    def setUp(self):
        self._fetch_called = False
        self._fetch_request = None
        super(ProxiedResponseTestCase, self).setUp()

    def stub_response(self, code, emulated_delay=0.1, **response_args):
        self._fetch_called = False
        self._fetch_request = None

        def _fetch_stub(http_client, request, callback):
            response = HTTPResponse(request=request, code=code, **response_args)
            self._fetch_request = request
            self._fetch_called = True
            self.io_loop.add_timeout(time.time() + emulated_delay, partial(callback, response))

        zaglushka._fetch_request = _fetch_stub

    def assertFetchCalled(self):
        self.assertTrue(self._fetch_called)

    def assertFetchUrl(self, url):
        self.assertIsNotNone(self._fetch_request)
        self.assertEqual(self._fetch_request.url, url)

    def tearDown(self):
        zaglushka._fetch_request = self._orig_fetch
        super(ProxiedResponseTestCase, self).tearDown()

    def get_zaglushka_config(self):
        return {
            'urls': [
                {
                    'path': '/fixed_proxy',
                    'method': 'POST',
                    'response_proxy': 'http://example.com/path.json',
                },
                {
                    'path_regexp': '^/re_proxy/(\d+)/(\w+).json$',
                    'response_proxy': 'http://re.example.com/resource/$2/$1/$1.js',
                },
                {
                    'path_regexp': '^/re_proxy2/(.*)$',
                    'response_proxy': 'http://re2.example.com/resource/$1.js',
                    'headers': {
                        'Overwrite': 'yes',
                        'Other': ['a', 'b']
                    }
                },
                {
                    'path': '/fixed_proxy2',
                    'response_proxy': 'http://f2.example.com:8008/resp',
                    'headers_file': path.join(TEST_RESOURCES_DIR, 'issue11.headers')
                },
                {
                    'path': '/delayed_proxy',
                    'method': 'PUT',
                    'response_proxy': 'http://example.com/path.json',
                    'delay': 0.5,
                },
            ]
        }

    def test_fixed_proxy(self):
        expected_headers = {'Host': 'my.example.com'}
        self.stub_response(code=200, buffer=StringIO('ok, ggl'), headers=expected_headers)
        response = self.fetch('/fixed_proxy', method='POST', body='')
        self.assertFetchCalled()
        self.assertResponseBody('ok, ggl', response)
        self.assertResponseHeaders(expected_headers, response)
        self.assertFetchUrl('http://example.com/path.json')

    def test_delayed_response(self):
        self.stub_response(code=httplib.NOT_FOUND, buffer=StringIO(':('))
        start = time.time()
        response = self.fetch('/delayed_proxy', method='PUT', body='')
        end = time.time()
        self.assertFetchCalled()
        self.assertResponseBody(':(', response)
        self.assertEqual(response.code, httplib.NOT_FOUND)
        self.assertGreaterEqual(end - start, 0.5)

    def test_regexp_proxy(self):
        self.stub_response(code=httplib.OK, buffer=StringIO('yup'))
        response = self.fetch('/re_proxy/12345/abcd.json')
        self.assertFetchCalled()
        self.assertResponseBody('yup', response)
        self.assertEqual(response.code, httplib.OK)
        self.assertFetchUrl('http://re.example.com/resource/abcd/12345/12345.js')

    def test_hardcoded_headers_overwrite(self):
        self.stub_response(code=httplib.OK, buffer=StringIO('over'), headers={'Unique': '1234', 'Overwrite': 'no'})
        response = self.fetch('/re_proxy2/ab/cd.html')
        self.assertFetchCalled()
        self.assertResponseBody('over', response)
        self.assertResponseHeaders(
            {
                'Unique': '1234',
                'Overwrite': 'yes',
                'Other': 'a,b',
            },
            response)
        self.assertFetchUrl('http://re2.example.com/resource/ab/cd.html.js')

    def test_filebased_headers_overwrite(self):
        self.stub_response(code=httplib.OK, buffer=StringIO(''), headers={'X-GITHUB-REQUEST-ID': 'abc', 'X-ID': '123'})
        response = self.fetch('/fixed_proxy2')
        self.assertFetchCalled()
        self.assertResponseBody('', response)
        self.assertResponseHeaders(
            {
                'Date': 'Wed, 23 Apr 2014 06: 13: 20 GMT',
                'X-GitHub-Request-Id': '53950898: 2E4E: 2AD562C: 535759FD',
                'X-Id': '123',
            },
            response)
        self.assertFetchUrl('http://f2.example.com:8008/resp')

    def test_response_error(self):
        self.stub_response(code=599, error=socket.error(61, 'Connection refused'))
        response = self.fetch('/fixed_proxy', method='POST', body='')
        self.assertFetchCalled()
        self.assertResponseBody('', response)
        self.assertResponseHeaders({'X-Zaglushka-Failed-Response': 'true'}, response)
        self.assertFetchUrl('http://example.com/path.json')
        self.assertInLogRecords(
            'Unable to proxy response to "http://example.com/path.json": [Errno 61] Connection refused',
            logger_name='zaglushka'
        )
