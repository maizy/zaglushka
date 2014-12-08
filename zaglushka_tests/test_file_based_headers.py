# coding: utf-8
from os import path

from zaglushka_tests import ZaglushkaAsyncHTTPTestCase, EXAMPLES_DIR, TEST_RESOURCES_DIR

RESPONSE_BODY = 'headers'


class FileBasedHeadersTestCase(ZaglushkaAsyncHTTPTestCase):

    HEADERS_ISSUE11 = {'Date': 'Wed, 23 Apr 2014 06: 13: 20 GMT',
                       'X-GitHub-Request-Id': '53950898: 2E4E: 2AD562C: 535759FD'}

    def get_zaglushka_config(self):
        return {
            'stubs_base_path': path.join(EXAMPLES_DIR, 'stubs'),
            'urls': [
                {
                    'path': '/headers',
                    'response': RESPONSE_BODY,
                    'headers_file': 'rate_limits.headers',
                },

                {
                    'path': '/issue-11',
                    'response': 'headers-issue11',
                    'headers_file': path.join(TEST_RESOURCES_DIR, 'issue11.headers'),
                }
            ]
        }

    def test_file_based_headers(self):
        response = self.fetch('/headers')
        self.assertResponseBody(RESPONSE_BODY, response)
        expected_headers = {
            'X-RateLimit-Limit': '5000',
            'X-RateLimit-Remaining': '4985',
            'X-Id': '123,abc,bcd'
        }
        self.assertResponseHeaders(expected_headers, response)

    def test_headers_with_doubledot(self):
        """
        issue #11: valid headers with : not parsed
        """
        response = self.fetch('/issue-11')
        self.assertEqual(response.code, 200)
        self.assertResponseBody('headers-issue11', response)
        self.assertResponseHeaders(self.HEADERS_ISSUE11, response)
