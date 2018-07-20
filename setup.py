#!/usr/bin/env python3
import os.path
import runpy

from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, "README.rst"), encoding="utf-8") as f:
    long_description = f.read()

version_mod = runpy.run_path("aioopenssl/version.py")

setup(
    name="aioopenssl",
    version=version_mod["__version__"],
    description="TLS-capable transport using OpenSSL for asyncio",
    long_description=long_description,
    url="https://github.com/horazont/aioopenssl",
    author="Jonas Wielicki",
    author_email="jonas@wielicki.name",
    license="Apache 2.0",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Operating System :: POSIX",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Communications :: Chat",
    ],
    keywords="openssl asyncio library transport starttls",
    install_requires=[
        "PyOpenSSL",
    ],
    packages=["aioopenssl"],
)
