# _*_ coding: utf-8 _*_
import sys
from os import path
import unittest

import pep8

_project_root = path.abspath(path.join(path.dirname(__file__), '..'))
_src_dirs = [path.join(_project_root, 'zaglushka.py'),
             path.join(_project_root, 'zaglushka_tests'),
             path.join(_project_root, 'setup.py')]


class StyleTestCase(unittest.TestCase):

    def test_pep8(self):
        pep8style = pep8.StyleGuide(
            show_pep8=False,
            show_source=True,
            repeat=True,
            max_line_length=120,
            statistics=True,
        )
        result = pep8style.check_files(_src_dirs)

        if result.total_errors > 0:
            sys.stderr.write('Statistics:\n{}\n'.format(result.get_statistics('')))
            self.fail('PEP8 styles errors')
