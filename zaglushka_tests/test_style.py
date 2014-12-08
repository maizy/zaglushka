# coding: utf-8
import sys
from os import path
import unittest

import pep8

from zaglushka_tests import PROJECT_ROOT

_src_dirs = [path.join(PROJECT_ROOT, 'zaglushka.py'),
             path.join(PROJECT_ROOT, 'zaglushka_tests'),
             path.join(PROJECT_ROOT, 'setup.py')]


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
