# coding: utf-8
from unittest import TestCase

from zaglushka import parse_options as parse_options


class ParseOptionsTestCase(TestCase):

    def tearDown(self):
        # reset tornado options state because it stored statically
        import tornado.options
        tornado.options.options = tornado.options.OptionParser()
        tornado.options.define_logging_options(tornado.options.options)

    def test_normal_params(self):
        args = ['zaglushka.py', '--ports=1234,5678', '--config=config.json']
        options = parse_options(args, err_func=lambda x: None)
        self.assertEqual(options.config, 'config.json')
        self.assertEqual(options.ports, [1234, 5678])

    def test_simple_config(self):
        args = ['zaglushka.py', 'config.json']
        options = parse_options(args, err_func=lambda x: None)
        self.assertEqual(options.config, 'config.json')
        self.assertEqual(options.ports, [8001])

    def test_simple_config_and_other_args(self):
        args = ['zaglushka.py', 'config.json', '--watch=false']
        options = parse_options(args, err_func=lambda x: None)
        self.assertEqual(options.config, 'config.json')
        self.assertEqual(options.ports, [8001])
        self.assertFalse(options.watch)

    def test_simple_config_and_ports(self):
        args = ['zaglushka.py', '~/config.json', '9001, 9111']
        options = parse_options(args, err_func=lambda x: None)
        self.assertEqual(options.config, '~/config.json')
        self.assertEqual(options.ports, [9001, 9111])

    def test_all_args(self):
        args = ['zaglushka.py', 'config.json', '8667,8888', '--watch=false']
        options = parse_options(args, err_func=lambda x: None)
        self.assertEqual(options.config, 'config.json')
        self.assertEqual(options.ports, [8667, 8888])
        self.assertFalse(options.watch)

    def test_more_than_two_simple_args(self):
        args = ['zaglushka.py', 'config.json', '8667,8888', 'false']
        errors = []
        options = parse_options(args, err_func=errors.append)
        self.assertIsNone(options)
        self.assertEqual(errors, ['More than two simple args'])

    def test_bad_port(self):
        args = ['zaglushka.py', 'config.json', '8667,abc']
        errors = []
        options = parse_options(args, err_func=errors.append)
        self.assertIsNone(options)
        self.assertEqual(errors, ['Wrong port value'])
