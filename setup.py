#/usr/bin/env python

from setuptools import setup, find_packages  # Always prefer setuptools over distutils
from codecs import open  # To use a consistent encoding
from os import path

setup(
    name='investigate',
    version='0.0.0',
    description='Interface for the OpenDNS Investigate API',
    url='https://github.com/dead10ck/pyinvestigate.git',
    author='Skyler Hawthorne',
    author_email='skylerhawthorne@gmail.com',
    license='MIT',
    keywords='opendns investigate',
    packages=find_packages(),
    install_requires=['requests'],
)
