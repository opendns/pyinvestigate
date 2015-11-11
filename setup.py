#!/usr/bin/env python

from setuptools import setup, find_packages  # Always prefer setuptools over distutils

setup(
    name='investigate',
    version='1.1.3',
    description='Python interface for the OpenDNS Investigate API',
    url='https://github.com/dead10ck/pyinvestigate.git',
    author='Skyler Hawthorne, Thibault Reuille',
    author_email='skylerhawthorne@gmail.com, thibault@opendns.com',
    license='MIT',
    keywords='opendns investigate',
    packages=find_packages(),
    install_requires=['requests'],
)
