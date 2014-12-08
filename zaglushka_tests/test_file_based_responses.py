# coding: utf-8
from os import path

from zaglushka_tests import ZaglushkaAsyncHTTPTestCase, EXAMPLES_DIR, read_example


class _BaseResponseFileTestCase(ZaglushkaAsyncHTTPTestCase):

    def test_simple_response_file(self):
        response = self.fetch('/ok')
        self.assertResponseBody(read_example('stubs/ok.txt'), response)

    def test_response_file_with_dot_slash(self):
        response = self.fetch('/error')
        self.assertResponseBody(read_example('stubs/error.txt'), response)


class ResponseFileAbsoluteStubsPathTestCase(_BaseResponseFileTestCase):

    def get_zaglushka_config(self):
        return {
            'stubs_base_path': path.join(EXAMPLES_DIR, 'stubs'),
            'urls': [
                {
                    'path': '/ok',
                    'response_file': 'ok.txt',
                },
                {
                    'path': '/error',
                    'response_file': 'error.txt',
                    'code': 503,
                },
            ]
        }

    def test_stubs_base_path(self):
        config = self.get_config_object()
        self.assertEqual(config.stubs_base_path, path.join(EXAMPLES_DIR, 'stubs'))


class ResponseFileStubsPathRelativeToConfigTestCase(_BaseResponseFileTestCase):

    def get_zaglushka_config_pseudo_path(self):
        return path.join(EXAMPLES_DIR, 'pseudo_config.json')

    def get_zaglushka_config(self):
        return {
            'stubs_base_path': './stubs',
            'urls': [
                {
                    'path': '/ok',
                    'response_file': 'ok.txt',
                },
                {
                    'path': '/error',
                    'response_file': './error.txt',
                    'code': 503,
                },
            ]
        }

    def test_stubs_base_path(self):
        config = self.get_config_object()
        self.assertEqual(config.stubs_base_path, path.join(EXAMPLES_DIR, 'stubs'))


class ResponseFileDefaultStubsPathTestCase(_BaseResponseFileTestCase):

    def get_zaglushka_config_pseudo_path(self):
        return path.join(EXAMPLES_DIR, 'pseudo_config.json')

    def get_zaglushka_config(self):
        return {
            'urls': [
                {
                    'path': '/ok',
                    'response_file': 'stubs/ok.txt',
                },
                {
                    'path': '/error',
                    'response_file': './stubs/error.txt',
                    'code': 503,
                },
            ]
        }

    def test_stubs_base_path(self):
        config = self.get_config_object()
        self.assertEqual(config.stubs_base_path, EXAMPLES_DIR)
