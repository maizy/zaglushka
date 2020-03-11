# coding: utf-8

from urllib.parse import quote

from zaglushka_tests import ZaglushkaAsyncHTTPTestCase


class SimpleRuleTestCase(ZaglushkaAsyncHTTPTestCase):

    def get_zaglushka_config(self):
        return {
            'urls': [

                # single params
                {
                    'path': '/path1',
                    'query': {
                        'required': {
                            'param1': 'abc',
                            'param2': 'def',
                        }
                    },
                    'response': 'path1',
                },
                {
                    'path': '/path1',
                    'response': 'path1_default',
                },

                # multiple params + regexp match
                {
                    'path_regexp': r'^/p[a-z]+h2$',
                    'query': {
                        'required': {
                            'param1': ['abc', 'def'],
                            'param2': 'xyz'
                        }
                    },
                    'response': 'path2',
                },

                # single params + regexp + other_allowed=false
                {
                    'path_regexp': r'^/p[a-z]+h3$',
                    'query': {
                        'required': {
                            'param1': 'abc',
                            'param2': 'def',
                        },
                        'other_allowed': False,
                    },
                    'response': 'path3',
                },

                # multiple params + other_allowed=false
                {
                    'path': '/path4',
                    'query': {
                        'required': {
                            'param1': 'abc',
                            'param2': ['def', 'ghi'],
                            'param3': ['jkl', 'mno']
                        },
                        'other_allowed': False,
                    },
                    'response': 'path4',
                },

                # empty params
                {
                    'path': '/path5',
                    'query': {
                        'required': {},
                    },
                    'response': 'path5',
                },

                {
                    'path': '/path6',
                    'query': {
                        'some_future_params': 'bla-bla-bla',
                    },
                    'response': 'path6',
                },

                # empty params + other_allowed=false (query string should be empty)
                {
                    'path': '/path7',
                    'query': {
                        'required': {},
                        'other_allowed': False,
                    },
                    'response': 'path7',
                },

                {
                    'path': '/path8',
                    'query': {
                        'other_allowed': False,
                    },
                    'response': 'path8',
                },

                # i8n params
                {
                    'path_regexp': '/path9',
                    'query': {
                        'required': {
                            'cyrillic': ['я', 'ю'],
                            'emoji': '💒'
                        }
                    },
                    'response': 'path9',
                },
            ]
        }

    def test_single_params(self):
        self.assertResponseBody('path1', self.fetch('/path1?param1=abc&param2=def'))
        self.assertResponseBody('path1', self.fetch('/path1?param2=def&param1=abc'))
        self.assertResponseBody('path1', self.fetch('/path1?param2=def&param2=def&param1=abc'))
        self.assertResponseBody('path1', self.fetch('/path1?param2=def&param1=abc&param3=123'))

        self.assertResponseBody('path1_default', self.fetch('/path1?param2=def'))
        self.assertResponseBody('path1_default', self.fetch('/path1?'))
        self.assertResponseBody('path1_default', self.fetch('/path1'))

    def test_multiple_params(self):
        self.assertResponseBody('path2', self.fetch('/paaaath2?param1=abc&param1=def&param2=xyz'))
        self.assertResponseBody('path2', self.fetch('/pth2?param1=abc&param1=def&param2=xyz&param3=boo'))
        self.assertResponseBody('path2', self.fetch('/pth2?param1=abc&param1=abc&param1=def&param2=xyz&param3=boo'))

        self.assertIsDefaultResponse(self.fetch('/path2?param1=abc&param1=fff&param2=xyz'))
        self.assertIsDefaultResponse(self.fetch('/path2?param1=abc&param2=xyz'))
        self.assertIsDefaultResponse(self.fetch('/path2?param1=def&param2=xyz'))
        self.assertIsDefaultResponse(self.fetch('/path2?param1=abc&param1=def&param2=zzz'))
        self.assertIsDefaultResponse(self.fetch('/path2?param2=xyz'))
        self.assertIsDefaultResponse(self.fetch('/path2'))

    def test_single_params_with_other_allowed_false(self):
        self.assertResponseBody('path3', self.fetch('/paaaaaath3?param1=abc&param2=def'))

        self.assertIsDefaultResponse(self.fetch('/paaaaaath3?param1=abc&param2=def&param2=def'))
        self.assertIsDefaultResponse(self.fetch('/paaaaaath3?param1=abc&param2=def&zoom=1234567'))
        self.assertIsDefaultResponse(self.fetch('/paaaaaath3?param1=ccc&param2=ddd'))
        self.assertIsDefaultResponse(self.fetch('/paaaaaath3?param1=abc&param1=a&param2=def'))
        self.assertIsDefaultResponse(self.fetch('/paaaaaath3?param1=abc'))
        self.assertIsDefaultResponse(self.fetch('/paaaaaath3'))

    def test_multiple_params_with_other_allowed_false(self):
        self.assertResponseBody('path4', self.fetch('/path4?param1=abc&param2=def&param2=ghi&param3=jkl&param3=mno'))

        self.assertIsDefaultResponse(
            self.fetch('/path4?param1=abc&param1=abc&param2=def&param2=ghi&param3=jkl&param3=mno'))
        self.assertIsDefaultResponse(self.fetch('/path4?param1=abc&param2=def&param2=ghi&param3=jkl&param3=mno&a=1'))
        self.assertIsDefaultResponse(self.fetch('/path4?param1=abc&param2=def&param2=ghi&param3=jkl'))
        self.assertIsDefaultResponse(self.fetch('/path4'))

    def test_empty_params(self):
        self.assertResponseBody('path5', self.fetch('/path5'))
        self.assertResponseBody('path6', self.fetch('/path6'))
        self.assertResponseBody('path5', self.fetch('/path5?'))
        self.assertResponseBody('path6', self.fetch('/path6?'))
        self.assertResponseBody('path6', self.fetch('/path6?unknown=true'))

    def test_empty_params_with_other_allowed_false(self):
        self.assertResponseBody('path7', self.fetch('/path7'))
        self.assertResponseBody('path8', self.fetch('/path8'))
        self.assertResponseBody('path7', self.fetch('/path7?'))
        self.assertResponseBody('path8', self.fetch('/path8?'))

        self.assertIsDefaultResponse(self.fetch('/path7?any=other'))
        self.assertIsDefaultResponse(self.fetch('/path8?any=other'))

    def test_international_params(self):

        def _e(x):
            return quote(x, encoding='utf-8')

        query = 'cyrillic=' + _e('я') + '&cyrillic=' + _e('ю') + '&emoji=' + _e('💒')
        self.assertResponseBody('path9', self.fetch('/path9?' + query))
