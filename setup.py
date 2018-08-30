#!/usr/bin/env python

import os
import sys
sys.version_info
from setuptools import setup, find_packages

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

install_requires = [
    'PycURL>=7.43.0',
    'rpmfile'
]

setup(
    name = "nexusupload",
    version = "0.1",
    author = "Fabrice Bacchella",
    author_email = "fabrice.bacchella@orange.fr",
    description = "Nexus uploader with kerberos/sso support.",
    license = "Apache",
    keywords = "Nexus rpm",
    install_requires = install_requires,
    url = "",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "nexusupload=nexuslib:main_wrap",
            "nexusupload%s=nexuslib:main_wrap" % sys.version[:1],
            "nexusupload%s=nexuslib:main_wrap" % sys.version[:3],
        ],
    },
    long_description=read('README.md'),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
        "License :: OSI Approved :: Apache Software License",
        "Classifier: Operating System :: OS Independent",
        "Environment :: Console",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: Implementation :: CPython",
    ],
    platforms=["Posix"],
)
