#!/usr/bin/env python
# coding: utf-8

from setuptools import setup

setup(
    name='requests-crtauth',
    version='0.1.1',
    packages=['requests_crtauth'],
    provides=['requests_crtauth'],
    install_requires=[
        'requests<=2.2.1',
        'crtauth>=0.1.2'
    ],
    author='Nic Cope',
    author_email='negz@spotify.com',
    description='HTTP crtauth authentication using the requests library.',
)
