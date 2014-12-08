# coding: utf-8
from zaglushka_tests import ZaglushkaAsyncHTTPTestCase


class DefaultResponseTestCase(ZaglushkaAsyncHTTPTestCase):

    def get_zaglushka_config(self):
        return {}

    def test_default_response(self):
        self.assertIsDefaultResponse(self.fetch('/path'))


class DefaultResponseBodyTestCase(ZaglushkaAsyncHTTPTestCase):

    def get_zaglushka_config(self):
        return {
            'urls': [
                {
                    'path': '/my_response',
                    'code': 500,
                    'headers': {
                        'X-Custom-Header': 'my;header',
                    }
                }
            ]
        }

    def test_default_response(self):
        response = self.fetch('/my_response')
        self.assertResponseBody(b'', response)
        self.assertEquals(500, response.code)
        self.assertResponseHeaders({'X-Custom-Header': 'my;header'}, response)
