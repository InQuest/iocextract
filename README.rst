iocextract
==========

.. image:: https://travis-ci.org/InQuest/python-iocextract.svg?branch=master
    :target: https://travis-ci.org/InQuest/python-iocextract
    :alt: Build Status
.. image:: https://readthedocs.org/projects/iocextract/badge/?version=latest
    :target: http://iocextract.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status
.. image:: https://api.codacy.com/project/badge/Grade/920894593bde451c9277c56b7d9ab3e1
    :target: https://app.codacy.com/app/InQuest/python-iocextract
    :alt: Code Health
.. image:: https://api.codacy.com/project/badge/Coverage/920894593bde451c9277c56b7d9ab3e1
    :target: https://app.codacy.com/app/InQuest/python-iocextract
    :alt: Test Coverage
.. image:: http://img.shields.io/pypi/v/iocextract.svg
    :target: https://pypi.python.org/pypi/iocextract
    :alt: PyPi Version

Advanced Indicator of Compromise (IOC) extractor.

Overview
--------

This library extracts URLs, IP addresses, MD5/SHA hashes, and YARA rules from
text corpora. It includes obfuscated and "defanged" IOCs in the output, and
optionally deobfuscates them.
