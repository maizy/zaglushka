# _*_ coding: utf-8 _*_
from logging import NullHandler

from tornado.testing import AsyncHTTPTestCase
from tornado.log import app_log, gen_log, access_log

from zaglushka import build_app, Config, logger as zaglushka_logger


class ZaglushkaAsyncHTTPTestCase(AsyncHTTPTestCase):

    class _CollectLoggingHandler(NullHandler):

        def __init__(self):
            self.records = []
            super(type(self), self).__init__()

        def handle(self, record):
            self.records.append(record)

    def get_zaglushka_config(self):
        raise NotImplementedError()

    def get_app(self):
        self.raw_config = self.get_zaglushka_config()
        self._log_handler = self._CollectLoggingHandler()
        for logger in (app_log, gen_log, access_log, zaglushka_logger):
            logger.addHandler(self._log_handler)
        return build_app(Config(self.raw_config))

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
        self.assertEqual(response.body, expected_body, 'Body not matched{}'.format(msg))
        real_len = int(response.headers['Content-Length'])
        expected_len = len(expected_body)
        self.assertEqual(real_len, expected_len,
                         'Body length not matched: {} != {}, {}'.format(real_len, expected_len, msg))

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
