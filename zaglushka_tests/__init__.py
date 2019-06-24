# coding: utf-8
from os import path
from logging import NullHandler

from tornado.testing import AsyncHTTPTestCase
from tornado.log import app_log, gen_log, access_log

from zaglushka import build_app, Config, logger as zaglushka_logger

PROJECT_ROOT = path.abspath(path.join(path.dirname(__file__), '..'))
EXAMPLES_DIR = path.join(PROJECT_ROOT, 'examples')
TEST_RESOURCES_DIR = path.join(PROJECT_ROOT, 'zaglushka_tests', 'resources')


def read_example(rel_path):
    file = open(path.join(EXAMPLES_DIR, rel_path), 'r')
    content = file.read()
    file.close()
    return content


class ZaglushkaAsyncHTTPTestCase(AsyncHTTPTestCase):

    class _CollectLoggingHandler(NullHandler):

        def __init__(self):
            self.records = []
            super(type(self), self).__init__()

        def handle(self, record):
            self.records.append(record)

    def get_zaglushka_config(self):
        raise NotImplementedError()

    def get_zaglushka_config_pseudo_path(self):
        return path.join(PROJECT_ROOT, 'zaglushka_tests', 'pseudo_config.json')

    def get_app(self):
        self.raw_config = self.get_zaglushka_config()
        self._log_handler = self._CollectLoggingHandler()
        for logger in (app_log, gen_log, access_log, zaglushka_logger):
            logger.addHandler(self._log_handler)
        config = Config(self.raw_config, self.get_zaglushka_config_pseudo_path())
        return build_app(config)

    def get_app_logs(self):
        return self._log_handler.records

    def get_config_object(self):
        """
        :rtype: zaglushka.Config
        """
        config = self._app.settings['zaglushka_config']
        self.assertIsInstance(config, Config)
        return config

    def assertResponseBody(self, expected_body, response, msg=''):
        msg = ': {}'.format(msg) if msg else ''
        expected_body = expected_body.encode('utf-8') if isinstance(expected_body, unicode) else expected_body
        self.assertEqual(expected_body, response.body, 'Body not matched {!r}!={!r} {}'
                         .format(expected_body, response.body, msg))
        real_len = int(response.headers['Content-Length'])
        expected_len = len(expected_body)
        self.assertEqual(expected_len, real_len,
                         'Body length not matched: {} != {}{}'.format(real_len, expected_len, msg))

    def assertResponseHeaders(self, expected_headers, response):
        real_headers = {key.lower(): value for key, value in response.headers.iteritems()}
        real_headers.pop('connection', None)
        expected_headers = {key.lower(): value for key, value in expected_headers.iteritems()}
        expected_headers['content-length'] = str(len(response.body))
        self.assertEqual(expected_headers, real_headers)

    def assertIsDefaultResponse(self, response):
        self.assertEqual(response.code, 404)
        self.assertResponseBody('', response)
        self.assertEqual(response.headers['X-Zaglushka-Default-Response'], 'true')

    def _search_first_log_record(self, logger_name, message):
        result = None
        for rec in self.get_app_logs():
            if rec.msg == message and (logger_name is None or rec.name == logger_name):
                result = rec
                break
        return result

    def assertInLogRecords(self, message, logger_name=None):
        rec = self._search_first_log_record(logger_name, message)
        if rec is None:
            self.fail('Unable to find log record with message: "{}" and name: "{}"'
                      .format(message, logger_name))

    def assertNotInLogRecords(self, message, logger_name=None):
        rec = self._search_first_log_record(logger_name, message)
        if rec is not None:
            self.fail('Log record with message: "{}" and name: "{}" found'
                      .format(message, logger_name))
