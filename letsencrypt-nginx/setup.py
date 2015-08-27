import sys

from setuptools import setup
from setuptools import find_packages


install_requires = [
    'acme',
    'letsencrypt',
    'pyparsing>=1.5.5',  # Python3 support; perhaps unnecessary?
    'zope.interface',
]

install_requires.append('mock<1.1.0')

setup(
    name='letsencrypt-nginx',
    packages=find_packages(),
    install_requires=install_requires,
    entry_points={
        'letsencrypt.plugins': [
            'nginx = letsencrypt_nginx.configurator:NginxConfigurator',
         ],
    },
    include_package_data=True,
)
