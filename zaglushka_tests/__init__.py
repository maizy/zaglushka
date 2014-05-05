# _*_ coding: utf-8 _*_
from tornado.testing import AsyncHTTPTestCase

from zaglushka import build_app, Config


class ZaglushkaAsyncHTTPTestCase(AsyncHTTPTestCase):

    def assertResponseBody(self, expected_body, response, msg=''):
        msg = ': {}'.format(msg) if msg else ''
        expected_body = expected_body.encode('utf-8') if isinstance(expected_body, unicode) else expected_body
        self.assertEqual(response.body, expected_body, 'Body not matched{}'.format(msg))
        real_len = int(response.headers['Content-Length'])
        expected_len = len(expected_body)
        self.assertEqual(real_len, expected_len,
                         'Body length not matched: {} != {}, {}'.format(real_len, expected_len, msg))

    def get_zaglushka_config(self):
        raise NotImplementedError()

    def get_app(self):
        self.raw_config = self.get_zaglushka_config()
        return build_app(Config(self.raw_config))
