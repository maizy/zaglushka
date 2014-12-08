# coding: utf-8
from zaglushka_tests import ZaglushkaAsyncHTTPTestCase


class ResponseCodesTestCase(ZaglushkaAsyncHTTPTestCase):

    def get_zaglushka_config(self):
        return {
            'urls': [
                {
                    'path': '/err500',
                    'response': '500',
                    'code': 500,
                },
                {
                    'path': '/err503',
                    'response': '503',
                    'code': 503,
                },
                {
                    'path': '/err400',
                    'response': '400',
                    'code': 400,
                },
            ]
        }

    def test_response_codes(self):
        for code in (500, 503, 400):
            response = self.fetch('/err{}'.format(code))
            self.assertEqual(response.code, code)
            self.assertResponseBody(str(code), response)
