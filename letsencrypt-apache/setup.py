import sys

from setuptools import setup
from setuptools import find_packages


install_requires = [
    'acme',
    'letsencrypt',
    'python-augeas',
    'zope.component',
    'zope.interface',
]

install_requires.append('mock<1.1.0')

setup(
    name='letsencrypt-apache',
    packages=find_packages(),
    install_requires=install_requires,
    entry_points={
        'letsencrypt.plugins': [
            'apache = letsencrypt_apache.configurator:ApacheConfigurator',
         ],
    },
    include_package_data=True,
)
