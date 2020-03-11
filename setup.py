from setuptools import setup

_version = '0.0.7'

setup(
    name='zaglushka',
    version=_version,
    install_requires=['tornado>=5.1,<6.1'],
    scripts=['zaglushka.py'],
    exclude=['zaglushka_tests/*'],
    author='Nikita Kovaliov',
    author_email='nikita@maizy.ru',
    description='Http server for stubing backends and emulate some errors',
    license='MIT',
    download_url='https://github.com/maizy/zaglushka/tarball/{}'.format(_version),
    keywords='stubs api zaglushka',
    url='https://github.com/maizy/zaglushka',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'License :: OSI Approved :: MIT License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: HTTP Servers',
        'Topic :: Software Development :: Testing',
    ],
    long_description='''\
Http server for stubing backends and emulate some errors.

`Documentation & examples at github <https://github.com/maizy/zaglushka>`__
''',
)
