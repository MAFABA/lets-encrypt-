import sys

from setuptools import setup
from setuptools import find_packages


install_requires = []
install_requires.append('mock<1.1.0')

setup(
    name='letshelp-letsencrypt',
    packages=find_packages(),
    install_requires=install_requires,
    entry_points={
        'console_scripts': [
            'letshelp-letsencrypt-apache = letshelp_letsencrypt.apache:main',
        ],
    },
    include_package_data=True,
)
