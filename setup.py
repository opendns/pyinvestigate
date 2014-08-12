#!/usr/bin/env python

from setuptools import setup, find_packages  # Always prefer setuptools over distutils
from codecs import open  # To use a consistent encoding
import os

with open('requirements.txt') as f:
    required = f.read().splitlines()

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name='investigate',
    version='1.0.0',
    description='Python interface for the OpenDNS Investigate API',
    long_description=read("README.md"),
    url='https://github.com/dead10ck/pyinvestigate.git',
    author='Skyler Hawthorne',
    author_email='skylerhawthorne@gmail.com',
    license='MIT',
    keywords='opendns investigate',
    packages=find_packages(),
    install_requires=required,
)
