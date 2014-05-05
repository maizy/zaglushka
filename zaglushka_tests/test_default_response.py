# _*_ coding: utf-8 _*_
from zaglushka_tests import ZaglushkaAsyncHTTPTestCase


class DefaultResponseTestCase(ZaglushkaAsyncHTTPTestCase):

    def get_zaglushka_config(self):
        return {}

    def test_default_response(self):
        response = self.fetch('/path')
        self.assertEqual(response.code, 404)
        self.assertResponseBody('', response)
        self.assertEqual(response.headers['X-Zaglushka-Default-Response'], 'true')
