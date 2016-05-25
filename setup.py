#!/usr/bin/env python

from setuptools import setup, find_packages  # Always prefer setuptools over distutils

setup(
    name='investigate',
    version='1.2.0',
    description='Python interface for the OpenDNS Investigate API',
    url='https://github.com/opendns/pyinvestigate',
    author='Skyler Hawthorne, Thibault Reuille',
    author_email='skylerhawthorne@gmail.com, thibault@opendns.com',
    license='MIT',
    keywords='opendns investigate',
    packages=find_packages(),
    install_requires=['requests'],
)
