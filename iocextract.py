"""Advanced Indicitor of Compromise (IOC) extractor

All methods return iterable objects, not lists. If for some reason you need
a list, do e.g.::

    >>> list(extract_iocs(my_data))
"""
import re
import itertools

# Get basic url format, including a few obfuscation techniques, main anchor is the uri scheme
GENERIC_URL_RE = re.compile(r"[fhstu]\w\w?[px]s?[:_]{1,2}\/\/\x20?\S+(?:\x20\/\S+)*(?=\s|$)")

# Get some obfuscated urls, main anchor is brackets around the period
BRACKET_URL_RE = re.compile(r"\b\S+(?:\x20?\[\x20?\.\x20?\]\x20?\S*)+(?=\s|$)")

# Get some obfuscated ip addresses
IP_RE = re.compile(r"\b(([1-9]?\d|1\d\d|2[0-4]\d|25[0-5])\[?\.\]?){3}([1-9]?\d|1\d\d|2[0-4]\d|25[0-5])\b")

EMAIL_RE = re.compile(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")
MD5_RE = re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{32})(?:[^a-fA-F\d]|\b)")
SHA1_RE = re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{40})(?:[^a-fA-F\d]|\b)")
SHA256_RE = re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{64})(?:[^a-fA-F\d]|\b)")
SHA512_RE = re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{128})(?:[^a-fA-F\d]|\b)")


def extract_iocs(data):
    """Extract all IOCs

    Results are returned as an itertools.chain iterable object which
    lazily provides the results of the other extract_* generators.

    :param str data: Input text
    :rtype: itertools.chain
    """
    return itertools.chain(
        extract_urls(data),
        extract_ips(data),
        extract_emails(data),
        extract_hashes(data)
    )

def extract_urls(data):
    """Extract URLs

    :param str data: Input text
    :rtype: generator
    """
    for url in GENERIC_URL_RE.finditer(data):
        yield(url.group(0))
    for url in BRACKET_URL_RE.finditer(data):
        yield(url.group(0))

def extract_ips(data):
    """Extract IP addresses

    :param str data: Input text
    :rtype: generator
    """
    for ip in IP_RE.finditer(data):
        yield(ip.group(0))

def extract_emails(data):
    """Extract email addresses

    :param str data: Input text
    :rtype: generator
    """
    for email in EMAIL_RE.finditer(data):
        yield(email.group(0))

def extract_hashes(data):
    """Extract MD5/SHA hashes

    Results are returned as an itertools.chain iterable object which
    lazily provides the results of the other extract_*_hashes generators.

    :param str data: Input text
    :rtype: itertools.chain
    """
    return itertools.chain(
        extract_md5_hashes(data),
        extract_sha1_hashes(data),
        extract_sha256_hashes(data),
        extract_sha512_hashes(data)
    )

def extract_md5_hashes(data):
    """Extract MD5 hashes

    :param str data: Input text
    :rtype: generator
    """
    for md5 in MD5_RE.finditer(data):
        yield(md5.group(1))

def extract_sha1_hashes(data):
    """Extract SHA1 hashes

    :param str data: Input text
    :rtype: generator
    """
    for sha1 in SHA1_RE.finditer(data):
        yield(sha1.group(1))

def extract_sha256_hashes(data):
    """Extract SHA256 hashes

    :param str data: Input text
    :rtype: generator
    """
    for sha256 in SHA256_RE.finditer(data):
        yield(sha256.group(1))

def extract_sha512_hashes(data):
    """Extract SHA512 hashes

    :param str data: Input text
    :rtype: generator
    """
    for sha512 in SHA512_RE.finditer(data):
        yield(sha512.group(1))
