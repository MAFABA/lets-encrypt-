import sys

from setuptools import setup
from setuptools import find_packages


install_requires = [
    'letsencrypt',
    'letsencrypt-apache',
    'letsencrypt-nginx',
    'docker-py',
    'zope.interface',
]

install_requires.append('mock<1.1.0')

setup(
    name='letsencrypt-compatibility-test',
    packages=find_packages(),
    install_requires=install_requires,
    entry_points={
        'console_scripts': [
            'letsencrypt-compatibility-test = letsencrypt_compatibility_test.test_driver:main',
        ],
    },
)
