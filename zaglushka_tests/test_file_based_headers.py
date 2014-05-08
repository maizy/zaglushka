# _*_ coding: utf-8 _*_
from os import path

from zaglushka_tests import ZaglushkaAsyncHTTPTestCase, EXAMPLES_DIR

RESPONSE_BODY = 'headers'


class FileBasedHeadersTestCase(ZaglushkaAsyncHTTPTestCase):

    def get_zaglushka_config(self):
        return {
            'stubs_base_path': path.join(EXAMPLES_DIR, 'stubs'),
            'urls': [
                {
                    'path': '/headers',
                    'response': RESPONSE_BODY,
                    'headers_file': 'rate_limits.headers',
                },
            ]
        }

    def test_file_based_headers(self):
        response = self.fetch('/headers')
        self.assertResponseBody(RESPONSE_BODY, response)
        expected_headers = {
            'X-RateLimit-Limit': '5000',
            'X-RateLimit-Remaining': '4985',
        }
        self.assertResponseHeaders(expected_headers, response)
