# coding: utf-8
from zaglushka_tests import ZaglushkaAsyncHTTPTestCase


class RegExpMatchersTestCase(ZaglushkaAsyncHTTPTestCase):

    def get_zaglushka_config(self):
        return {
            'urls': [
                {
                    'path_regexp': r'^/letter_[a-z]+$',
                    'response': 'regexp1',
                },
                {
                    'path_regexp': r'^/letter_[z0-9]+$',
                    'response': 'regexp2',
                },
                {
                    'path_regexp': r'match_[a-z]+_where',
                    'response': 'regexp3',
                },
                {
                    'path_regexp': r'end$',
                    'response': 'regexp4',
                },
                {
                    'path_regexp': r'^/start',
                    'response': 'regexp5',
                },
            ]
        }

    def test_rule1(self):
        self.assertResponseBody('regexp1', self.fetch('/letter_a'))
        self.assertResponseBody('regexp1', self.fetch('/letter_zzz'))
        self.assertIsDefaultResponse(self.fetch('/letter_'))

    def test_rule2(self):
        self.assertResponseBody('regexp2', self.fetch('/letter_88'))
        self.assertIsDefaultResponse(self.fetch('/letter_'))

    def test_match_anywhere(self):
        self.assertResponseBody('regexp3', self.fetch('/path/aaa_match_any_where_bbb'))

    def test_match_end(self):
        self.assertResponseBody('regexp4', self.fetch('/path/to/end'))

    def test_match_start(self):
        self.assertResponseBody('regexp5', self.fetch('/start_with_any_path'))

    def test_default_response(self):
        response = self.fetch('/not_matched_path')
        self.assertIsDefaultResponse(response)


class RegExpMatchAnyTestCase(ZaglushkaAsyncHTTPTestCase):

    def get_zaglushka_config(self):
        return {
            'urls': [
                {
                    'path_regexp': r'.*',
                    'response': 'any',
                },
                {
                    'path_regexp': r'^/other$',
                    'response': 'wtf',
                },
            ]
        }

    def test_any_url_matched_rule(self):
        self.assertResponseBody('any', self.fetch('/path'))
        self.assertResponseBody('any', self.fetch('/other'))


class TestWrongRegexpTestCase(ZaglushkaAsyncHTTPTestCase):

    def get_zaglushka_config(self):
        return {
            'urls': [
                {
                    'path_regexp': r'^wrong_regexp[',
                    'response': 'wtf?',
                }
            ]
        }

    def test_default_rule_applied(self):
        self.assertIsDefaultResponse(self.fetch('/wrong_regexp['))

    def test_wrong_regexp(self):
        config = self.get_config_object()
        self.assertEqual(len(config.rules), 1)  # only default rule
        self.assertInLogRecords(
            message='Unable to compile regexp "^wrong_regexp["',
            logger_name='zaglushka',
            strict_match=False)
        self.assertInLogRecords(
            message='Unable to build matcher from url spec #0, skipping',
            logger_name='zaglushka')
