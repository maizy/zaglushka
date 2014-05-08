from setuptools import setup

setup(
    name='zaglushka',
    version='0.0.3',
    install_requires=['tornado>=3.2'],
    tests_require=['nose>=1.3', 'pep8>=1.3'],
    test_suite='nose.collector',
    scripts=['zaglushka.py'],
    exclude=['zaglushka_tests/*'],
    author='Nikita Kovaliov',
    author_email='nikita@maizy.ru',
    description='Simple python http server for API stubs',
    license='MIT',
    keywords='stubs api zaglushka',
    url='https://github.com/maizy/zaglushka',
)
