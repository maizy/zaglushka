# _*_ coding: utf-8 _*_
from zaglushka_tests import ZaglushkaAsyncHTTPTestCase


class DefaultResponseTestCase(ZaglushkaAsyncHTTPTestCase):

    def get_zaglushka_config(self):
        return {}

    def test_default_response(self):
        self.assertIsDefaultResponse(self.fetch('/path'))
