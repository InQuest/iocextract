iocextract
==========

.. image:: https://travis-ci.org/InQuest/python-iocextract.svg?branch=master
    :target: https://travis-ci.org/InQuest/python-iocextract
    :alt: Build Status
.. image:: https://api.codacy.com/project/badge/Grade/8b426dc1be7647ba8c51f4ccbd7b85bf
    :target: https://www.codacy.com/app/rshipp/python-iocextract
    :alt: Code Health
.. image:: https://api.codacy.com/project/badge/Coverage/8b426dc1be7647ba8c51f4ccbd7b85bf
    :target: https://www.codacy.com/app/rshipp/python-iocextract
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
