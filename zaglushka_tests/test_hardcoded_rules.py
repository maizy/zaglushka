# coding: utf-8
import json

from zaglushka_tests import ZaglushkaAsyncHTTPTestCase


class SimpleRuleTestCase(ZaglushkaAsyncHTTPTestCase):

    BODY_1 = u'body 1'
    BODY_2 = u'body unicode абвгдеёЖЗИЙклм'

    def get_zaglushka_config(self):
        return {
            'urls': [
                {
                    'path': '/relative/path',
                    'response': self.BODY_1,
                },
                {
                    'path': '/relative/path2',
                    'response': self.BODY_2,
                },
                {
                    'path': '/hardcoded_json',
                    'response': {
                        u'some': u'json',
                        u'ключ': u'значение',
                    },
                },
                {
                    'path': '/hardcoded_headers',
                    'response': u'hardcoded_headers',
                    'headers': {
                        'X-Custom-Header': 'my;header',
                        'Content-Type': 'application/x-myapp',
                        'Server': 'MyServer/0.1',
                    }
                }
            ]
        }

    def test_path_match_and_hardcoded_ascii_response(self):
        response = self.fetch('/relative/path')
        self.assertEqual(response.code, 200)
        self.assertResponseBody(self.BODY_1, response)

    def test_path_match_and_hardcoded_unicode_response(self):
        response = self.fetch('/relative/path2')
        self.assertEqual(response.code, 200)
        self.assertResponseBody(self.BODY_2, response)

    def test_path_match_and_hardcoded_json_response(self):
        response = self.fetch('/hardcoded_json')
        self.assertEqual(response.code, 200)
        expected_body = json.dumps(self.raw_config['urls'][2]['response'], ensure_ascii=False)
        self.assertResponseBody(expected_body, response)

    def test_path_match_and_hardcoded_headers(self):
        response = self.fetch('/hardcoded_headers')
        self.assertEqual(response.code, 200)
        self.assertResponseBody('hardcoded_headers', response)
        self.assertResponseHeaders(self.raw_config['urls'][3]['headers'], response)


class MultipleHeadersTestCase(ZaglushkaAsyncHTTPTestCase):

    def get_zaglushka_config(self):
        return {
            'urls': [
                {
                    'path': '/response_1',
                    'headers': {
                        'X-Custom-Header': 'my;header',
                        'X-Id': ['23', 'abc']
                    },
                    'response': 'response1'
                },
            ]
        }

    def test_hardcoded_multiple_headers(self):
        response = self.fetch('/response_1')
        self.assertResponseBody(b'response1', response)
        self.assertResponseHeaders(
            {
                'X-Custom-Header': 'my;header',
                'X-Id': '23,abc',
            },
            response
        )
