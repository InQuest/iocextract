"""Extract and optionallly defang Indicators of Compromise (IOCs) from text.

All methods return iterator objects, not lists. If for some reason you need
a list, do e.g.: ``list(extract_iocs(my_data))``.

Otherwise, you can iterate over the objects (e.g. in a ``for`` loop) normally.
Each object yielded from the generators will by of type :class:`str`.
"""
import re
import itertools

# Get basic url format, including a few obfuscation techniques, main anchor is the uri scheme
GENERIC_URL_RE = re.compile(r"[fhstu]\w\w?[px]s?(?::\/\/|__?)\x20?\S+(?:\x20[\/\.]\S+)*(?=\s|$)")

# Get some obfuscated urls, main anchor is brackets around the period
BRACKET_URL_RE = re.compile(r"\b\S+(?:\x20?[\(\[]\x20?\.\x20?[\]\)]\x20?\S*)+(?=\s|$)")

# Get some valid obfuscated ip addresses
IPV4_RE = re.compile(r"(?:^|(?![^\d\.]))(?:(?:[1-9]?\d|1\d\d|2[0-4]\d|25[0-5])[\[\(]?\.[\]\)]?){3}(?:[1-9]?\d|1\d\d|2[0-4]\d|25[0-5])(?:(?=[^\d\.])|$)")

# Experimental IPV6 regex, will not catch everything but should be sufficent for now
IPV6_RE = re.compile(r"\b(?:[a-f0-9]{1,4}:|:){2,7}(?:[a-f0-9]{1,4}|:)\b")

EMAIL_RE = re.compile(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")
MD5_RE = re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{32})(?:[^a-fA-F\d]|\b)")
SHA1_RE = re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{40})(?:[^a-fA-F\d]|\b)")
SHA256_RE = re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{64})(?:[^a-fA-F\d]|\b)")
SHA512_RE = re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{128})(?:[^a-fA-F\d]|\b)")

# YARA regex
YARA_SPLIT_STR = "\n[\t\s]*\}[\s\t]*(rule[\t\s][^\r\n]+(?:\{|[\r\n][\r\n\s\t]*\{))"
YARA_PARSE_RE = re.compile(r"^[\t\s]*(rule[\t\s][^\r\n]+(?:\{|[\r\n][\r\n\s\t]*\{).*?condition:.*?\r?\n?[\t\s]*\})[\s\t]*(?:$|\r?\n)", re.MULTILINE | re.DOTALL)


def extract_iocs(data):
    """Extract all IOCs.

    Results are returned as an itertools.chain iterable object which
    lazily provides the results of the other extract_* generators.

    :param data: Input text
    :rtype: :py:func:`itertools.chain`
    """
    return itertools.chain(
        extract_urls(data),
        extract_ips(data),
        extract_emails(data),
        extract_hashes(data),
        extract_yara_rules(data)
    )

def extract_urls(data):
    """Extract URLs.

    :param data: Input text
    :rtype: Iterator[:class:`str`]
    """
    for url in GENERIC_URL_RE.finditer(data):
        yield(url.group(0))
    for url in BRACKET_URL_RE.finditer(data):
        yield(url.group(0))

def extract_ips(data):
    """Extract IP addresses.

    Includes both IPv4 and IPv6 addresses.

    :param data: Input text
    :rtype: :py:func:`itertools.chain`
    """
    return itertools.chain(
        extract_ipv4s(data),
        extract_ipv6s(data),
    )

def extract_ipv4s(data):
    """Extract IPv4 addresses.

    :param data: Input text
    :rtype: Iterator[:class:`str`]
    """
    for ip in IPV4_RE.finditer(data):
        yield(ip.group(0))

def extract_ipv6s(data):
    """Extract IPv6 addresses.

    Not guaranteed to catch all valid IPv6 addresses.

    :param data: Input text
    :rtype: Iterator[:class:`str`]
    """
    for ip in IPV6_RE.finditer(data):
        yield(ip.group(0))

def extract_emails(data):
    """Extract email addresses

    :param data: Input text
    :rtype: Iterator[:class:`str`]
    """
    for email in EMAIL_RE.finditer(data):
        yield(email.group(0))

def extract_hashes(data):
    """Extract MD5/SHA hashes.

    Results are returned as an itertools.chain iterable object which
    lazily provides the results of the other extract_*_hashes generators.

    :param data: Input text
    :rtype: :py:func:`itertools.chain`
    """
    return itertools.chain(
        extract_md5_hashes(data),
        extract_sha1_hashes(data),
        extract_sha256_hashes(data),
        extract_sha512_hashes(data)
    )

def extract_md5_hashes(data):
    """Extract MD5 hashes.

    :param data: Input text
    :rtype: Iterator[:class:`str`]
    """
    for md5 in MD5_RE.finditer(data):
        yield(md5.group(1))

def extract_sha1_hashes(data):
    """Extract SHA1 hashes.

    :param data: Input text
    :rtype: Iterator[:class:`str`]
    """
    for sha1 in SHA1_RE.finditer(data):
        yield(sha1.group(1))

def extract_sha256_hashes(data):
    """Extract SHA256 hashes.

    :param data: Input text
    :rtype: Iterator[:class:`str`]
    """
    for sha256 in SHA256_RE.finditer(data):
        yield(sha256.group(1))

def extract_sha512_hashes(data):
    """Extract SHA512 hashes.

    :param data: Input text
    :rtype: Iterator[:class:`str`]
    """
    for sha512 in SHA512_RE.finditer(data):
        yield(sha512.group(1))

def extract_yara_rules(data):
    """Extract YARA rules.

    :param data: Input text
    :rtype: Iterator[:class:`str`]
    """
    yara_rules = re.sub(YARA_SPLIT_STR, "}\r\n\\1", data,
                        re.MULTILINE | re.DOTALL)
    for yara_rule in YARA_PARSE_RE.finditer(yara_rules):
        yield(yara_rule.group(1))
