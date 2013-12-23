#!/usr/bin/env python
# coding: utf-8

from setuptools import setup

setup(
    name='requests_crtauth',
    version='0.0.1',
    packages=['requests_crtauth'],
    provides=['requests_crtauth'],
    install_requires=[
        'requests>=1.0.0',
        'crtauth>=0.1.2'
    ],
    author='Nic Cope',
    author_email='negz@spotify.com',
    description='HTTP crtauth authentication using the requests library.',
)
