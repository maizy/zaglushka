# _*_ coding: utf-8 _*_
import time

from zaglushka_tests import ZaglushkaAsyncHTTPTestCase


class DelayedResponseTestCase(ZaglushkaAsyncHTTPTestCase):

    def get_zaglushka_config(self):
        return {
            'urls': [
                {
                    'path': '/long_response',
                    'response': 'some res',
                    'delay': 0.5
                }
            ]
        }

    def test_delayed_response(self):
        start = time.time()
        self.assertResponseBody('some res', self.fetch('/long_response'))
        end = time.time()
        self.assertGreaterEqual(end-start, 0.5)
