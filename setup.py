#!/usr/bin/env python3
import os.path

from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, "README.rst"), encoding="utf-8") as f:
    long_description = f.read()

from aioopenssl import __version__

setup(
    name="aioopenssl",
    version=__version__,
    description="TLS-capable transport using OpenSSL for asyncio",
    long_description=long_description,
    url="https://github.com/horazont/aioopenssl",
    author="Jonas Wielicki",
    author_email="jonas@wielicki.name",
    license="Apache 2.0",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Operating System :: POSIX",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Topic :: Communications :: Chat",
    ],
    keywords="openssl asyncio library transport starttls",
    packages=["aioopenssl"],
)
