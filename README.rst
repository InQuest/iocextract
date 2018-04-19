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

Usage
-----

Try extracting some defanged URLS::

    >>> content = """
    ... I really love example[.]com!
    ... All the bots are on hxxp://example.com/bad/url these days.
    ... C2: tcp://example[.]com:8989/bad
    ... """
    >>> import iocextract
    >>> for url in iocextract.extract_urls(content):
    ...     print url
    ...
    hxxp://example.com/bad/url
    tcp://example[.]com:8989/bad
    example[.]com
    tcp://example[.]com:8989/bad

Note that some URLs may show up twice if they are caught by multiple REGEXes.

If you want, you can also "refang", or remove common obfuscation methods from
IOCs::

    >>> for url in iocextract.extract_urls(content, refang=True):
    ...     print url
    ...
    http://example.com/bad/url
    http://example.com:8989/bad
    http://example.com
    http://example.com:8989/bad

All ``extract_*`` functions in this library return iterators, not lists. The
benefit of this behavior is that ``iocextract`` can process extremely large
inputs, with a very low overhead. However, if for some reason you need to iterate
over the IOCs more than once, you will have to save the results as a list::

    >>> list(iocextract.extract_urls(content))
    ['hxxp://example.com/bad/url', 'tcp://example[.]com:8989/bad', 'example[.]com', 'tcp://example[.]com:8989/bad']
