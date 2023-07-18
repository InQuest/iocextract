"""
Extract and optionally refang Indicators of Compromise (IOCs) from text.

All methods return iterator objects, not lists.
If for some reason you need a list, you can specify like so: `list(extract_iocs(my_data))`

Otherwise, you can iterate over the objects (e.g. in a `for` loop) normally. Each object yielded from the generators will be of type `str`.
"""

import io
import os
import sys
import json
import base64
import random
import string
import argparse
import requests
import binascii
import itertools
import ipaddress
import regex as re

from pathlib import Path
from string import whitespace

try:
    # Python 3
    from urllib.parse import urlparse, unquote

    unicode = str
except ImportError:
    # Python 2
    from urlparse import urlparse
    from urllib import unquote

# Reusable end punctuation regex
END_PUNCTUATION = r"[\.\?>\"'\)!,}:;\u201d\u2019\uff1e\uff1c\]]*"

# Reusable regex for symbols commonly used to defang
SEPARATOR_DEFANGS = r"[\(\)\[\]{}<>\\]"

# Split URLs on some characters that may be valid, but may also be garbage
URL_SPLIT_STR = r"[>\"'\),};]"

# Checks for whitespace and trailing characters after the URL
WS_SYNTAX_RM = re.compile(r"\s+/[a-zA-Z]")


def url_re(open_punc=False):
    """
    Modified URL regex based on if end puncuation is needed or not.
    """

    if open_punc:
        # Get basic url format, including a few obfuscation techniques, main anchor is the uri scheme
        GENERIC_URL_RE = re.compile(
            r"""
        (
            # Scheme
            [fhstu]\S\S?[px]s?

            # One of these delimiters/defangs
            (?:
                :\/\/|
                :\\\\|
                \[:\]\/\/|
                :?__
            )

            # Any number of defang characters
            (?:
                \x20|
                """
            + SEPARATOR_DEFANGS
            + r"""
            )*

            # Domain/path characters
            \w
            \S+?

            # CISCO ESA style defangs followed by domain/path characters
            (?:\x20[\/\.][^\.\/\s]\S*?)*
        )
    """
            + r"""
        (?=\s|[^\x00-\x7F]|$)
    """,
            re.IGNORECASE | re.VERBOSE | re.UNICODE,
        )
    else:
        # Get basic url format, including a few obfuscation techniques, main anchor is the uri scheme
        GENERIC_URL_RE = re.compile(
            r"""
        (
            # Scheme.
            [fhstu]\S\S?[px]s?

            # One of these delimiters/defangs
            (?:
                :\/\/|
                :\\\\|
                \[:\]\/\/|
                :?__
            )

            # Any number of defang characters
            (?:
                \x20|
                """
            + SEPARATOR_DEFANGS
            + r"""
            )*

            # Domain/path characters
            \w
            \S+?

            # CISCO ESA style defangs followed by domain/path characters
            (?:\x20[\/\.][^\.\/\s]\S*?)*
        )
    """
            + END_PUNCTUATION
            + r"""
        (?=\s|[^\x00-\x7F]|$)
    """,
            re.IGNORECASE | re.VERBOSE | re.UNICODE,
        )

    return GENERIC_URL_RE


# Get some obfuscated urls, main anchor is brackets around the period
BRACKET_URL_RE = re.compile(
    r"""
    \b
    (
        [\.\:\/\\\w\[\]\(\)-]+
        (?:
            \x20?
            [\(\[]
            \x20?
            \.
            \x20?
            [\]\)]
            \x20?
            \S*?
        )+
    )
"""
    + END_PUNCTUATION
    + r"""
    (?=\s|[^\x00-\x7F]|$)
""",
    re.VERBOSE | re.UNICODE,
)

# Get some obfuscated urls, main anchor is backslash before a period
BACKSLASH_URL_RE = re.compile(
    r"""
    \b
    (
        [\.\:\/\\\w\[\]\(\)-]+
        (?:
            \x20?
            \\
            \x20?
            \.
            \x20?
            \S*?
        )+
    )
"""
    + END_PUNCTUATION
    + r"""
    (?=\s|[^\x00-\x7F]|$)
""",
    re.VERBOSE | re.UNICODE,
)

# Get hex-encoded urls
HEXENCODED_URL_RE = re.compile(
    r"""
    (
        [46][86]
        (?:[57]4)?
        [57]4[57]0
        (?:[57]3)?
        3a2f2f
        (?:2[356def]|3[0-9adf]|[46][0-9a-f]|[57][0-9af])+
    )
    (?:[046]0|2[0-2489a-c]|3[bce]|[57][b-e]|[8-f][0-9a-f]|0a|0d|09|[
        \x5b-\x5d\x7b\x7d\x0a\x0d\x20
    ]|$)
""",
    re.IGNORECASE | re.VERBOSE,
)

# Get urlencoded urls
URLENCODED_URL_RE = re.compile(
    r"(s?[hf]t?tps?%3A%2F%2F\w[\w%-]*?)(?:[^\w%-]|$)", re.IGNORECASE | re.VERBOSE
)

# Get base64-encoded urls
B64ENCODED_URL_RE = re.compile(
    r"""
    (
        # b64re '([hH][tT][tT][pP][sS]|[hH][tT][tT][pP]|[fF][tT][pP])://'
        # Modified to ignore whitespace
        (?:
            [\x2b\x2f-\x39A-Za-z]\s*[\x2b\x2f-\x39A-Za-z]\s*[\x31\x35\x39BFJNRVZdhlptx]\s*[Gm]\s*[Vd]\s*[FH]\s*[A]\s*\x36\s*L\s*y\s*[\x2b\x2f\x38-\x39]\s*|
            [\x2b\x2f-\x39A-Za-z]\s*[\x2b\x2f-\x39A-Za-z]\s*[\x31\x35\x39BFJNRVZdhlptx]\s*[Io]\s*[Vd]\s*[FH]\s*[R]\s*[Qw]\s*[O]\s*i\s*\x38\s*v\s*[\x2b\x2f-\x39A-Za-z]\s*|
            [\x2b\x2f-\x39A-Za-z]\s*[\x2b\x2f-\x39A-Za-z]\s*[\x31\x35\x39BFJNRVZdhlptx]\s*[Io]\s*[Vd]\s*[FH]\s*[R]\s*[Qw]\s*[Uc]\s*[z]\s*o\s*v\s*L\s*[\x2b\x2f-\x39w-z]\s*|
            [\x2b\x2f-\x39A-Za-z]\s*[\x30\x32EGUWkm]\s*[Z]\s*[\x30U]\s*[Uc]\s*[D]\s*o\s*v\s*L\s*[\x2b\x2f-\x39w-z]\s*|
            [\x2b\x2f-\x39A-Za-z]\s*[\x30\x32EGUWkm]\s*[h]\s*[\x30U]\s*[Vd]\s*[FH]\s*[A]\s*\x36\s*L\s*y\s*[\x2b\x2f\x38-\x39]\s*|
            [\x2b\x2f-\x39A-Za-z]\s*[\x30\x32EGUWkm]\s*[h]\s*[\x30U]\s*[Vd]\s*[FH]\s*[B]\s*[Tz]\s*[O]\s*i\s*\x38\s*v\s*[\x2b\x2f-\x39A-Za-z]\s*|
            [RZ]\s*[ln]\s*[R]\s*[Qw]\s*[O]\s*i\s*\x38\s*v\s*[\x2b\x2f-\x39A-Za-z]\s*|
            [Sa]\s*[FH]\s*[R]\s*[\x30U]\s*[Uc]\s*[D]\s*o\s*v\s*L\s*[\x2b\x2f-\x39w-z]\s*|
            [Sa]\s*[FH]\s*[R]\s*[\x30U]\s*[Uc]\s*[FH]\s*[M]\s*\x36\s*L\s*y\s*[\x2b\x2f\x38-\x39]\s*
        )
        # Up to 260 characters (pre-encoding, reasonable URL length)
        [A-Za-z0-9+/=\s]{1,357}
    )
    (?=[^A-Za-z0-9+/=\s]|$)
""",
    re.VERBOSE,
)

# Get defanged https URL schemes
HTTPS_SCHEME_DEFANG_RE = re.compile("hxxps", re.IGNORECASE)


# Get some valid obfuscated ip addresses
def ipv4_len(ip_len=3):
    # Monitors the octet pattern of the extracted IP addresses
    if ip_len == 3:
        IPV4_RE = re.compile(
            r"""
            (?:^|
                (?![^\d\.])
            )
            (?:
                (?:[1-9]?\d|1\d\d|2[0-4]\d|25[0-5])
                [\[\(\\]*?\.[\]\)]*?
            ){3}
            (?:[1-9]?\d|1\d\d|2[0-4]\d|25[0-5])
            (?:(?=[^\d\.])|$)
        """,
            re.VERBOSE,
        )

    elif ip_len == 4:
        IPV4_RE = re.compile(
            r"""
            (?:^|
                (?![^\d\.])
            )
            (?:
                (?:[1-9]?\d|1\d\d|2[0-4]\d|25[0-5])
                [\[\(\\]*?\.[\]\)]*?
            ){4}
            ([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])
            (?:[1-9]?\d|1\d\d|2[0-4]\d|25[0-5])
            (?:(?=[^\d\.])|$)
        """,
            re.VERBOSE,
        )

    return IPV4_RE


# Experimental IPv6 regex, will not catch everything but should be sufficent for now
IPV6_RE = re.compile(
    r"\b(?:[a-f0-9]{1,4}:|:){2,7}(?:[a-f0-9]{1,4}|:)\b", re.IGNORECASE | re.VERBOSE
)

# Capture email addresses including common defangs
EMAIL_RE = re.compile(
    r"""
    (
        [a-z0-9_.+-]+
        [\(\[{\x20]*
        (?:
            (?:
                (?:
                    \x20*
                    """
    + SEPARATOR_DEFANGS
    + r"""
                    \x20*
                )*
                \.
                (?:
                    \x20*
                    """
    + SEPARATOR_DEFANGS
    + r"""
                    \x20*
                )*
                |
                \W+dot\W+
            )
            [a-z0-9-]+?
        )*
        [a-z0-9_.+-]+
        [\(\[{\x20]*
        (?:@|\Wat\W)
        [\)\]}\x20]*
        [a-z0-9-]+
        (?:
            (?:
                (?:
                    \x20*
                    """
    + SEPARATOR_DEFANGS
    + r"""
                    \x20*
                )*
                \.
                (?:
                    \x20*
                    """
    + SEPARATOR_DEFANGS
    + r"""
                    \x20*
                )*
                |
                \W+dot\W+
            )
            [a-z0-9-]+?
        )+
    )
"""
    + END_PUNCTUATION
    + r"""
    (?=\s|$)
""",
    re.IGNORECASE | re.VERBOSE | re.UNICODE,
)

MD5_RE = re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{32})(?:[^a-fA-F\d]|\b)")
SHA1_RE = re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{40})(?:[^a-fA-F\d]|\b)")
SHA256_RE = re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{64})(?:[^a-fA-F\d]|\b)")
SHA512_RE = re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{128})(?:[^a-fA-F\d]|\b)")

# YARA regex.
YARA_PARSE_RE = re.compile(
    r"""
    (?:^|\s)
    (
        (?:
            \s*?import\s+?"[^\r\n]*?[\r\n]+|
            \s*?include\s+?"[^\r\n]*?[\r\n]+|
            \s*?//[^\r\n]*[\r\n]+|
            \s*?/\*.*?\*/\s*?
        )*
        (?:
            \s*?private\s+|
            \s*?global\s+
        )*
        rule\s*?
        \w+\s*?
        (?:
            :[\s\w]+
        )?
        \s+\{
        .*?
        condition\s*?:
        .*?
        \s*\}
    )
    (?:$|\s)
""",
    re.MULTILINE | re.DOTALL | re.VERBOSE,
)

TELEPHONE_RE = re.compile(r"((?:(?:\+?1\s*(?:[.-]\s*)?)?(?:\(\s*([2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9])\s*\)|([2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9]))\s*(?:[.-]\s*)?)?([2-9]1[02-9]|[2-9][02-9]1|[2-9][02-9]{2})\s*(?:[.-]\s*)?([0-9]{4})(?:\s*(?:#|x\.?|ext\.?|extension)\s*(\d+))?)")


def extract_iocs(data, refang=False, strip=False):
    """
    Extract all IOCs!

    Results are returned as an itertools.chain iterable object which
    lazily provides the results of the other extract_* generators.

    :param data: Input text
    :param bool refang: Refang output
    :param bool strip: Strip possible garbage from the end of URLs
    :rtype: :py:func:`itertools.chain`
    """

    return itertools.chain(
        extract_urls(data, refang=refang, strip=strip),
        extract_ips(data, refang=refang),
        extract_emails(data, refang=refang),
        extract_hashes(data),
        extract_yara_rules(data),
        extract_telephone_nums(data)
    )


def extract_urls(
    data,
    refang=False,
    strip=False,
    delimiter=False,
    open_punc=False,
    no_scheme=False,
    defang=False,
):
    """
    Extract URLs!

    NOTE: During extraction, if IPv4 addresses are present, you may extract some of those as well.

    :param data: Input text
    :param bool refang: Refang output
    :param bool strip: Strip possible garbage from the end of URLs
    :param bool delimiter: Continue extracting even after whitespace is detected
    :param bool open_punc: Disabled puncuation regex
    :param bool no_scheme: Remove protocol (http, tcp, etc.) type in output
    :param bool defang: Extract non-defanged IOCs
    :rtype: :py:func:`itertools.chain`
    """

    return itertools.chain(
        extract_unencoded_urls(
            data,
            refang=refang,
            strip=strip,
            open_punc=open_punc,
            no_scheme=no_scheme,
            defang=defang,
        ),
        extract_encoded_urls(data, refang=refang, strip=strip, delimiter=delimiter),
    )


def extract_unencoded_urls(
    data, refang=False, strip=False, open_punc=False, no_scheme=False, defang=False
):
    """
    Extract only unencoded URLs!

    :param data: Input text
    :param bool refang: Refang output
    :param bool strip: Strip possible garbage from the end of URLs
    :param bool open_punc: Disabled puncuation regex
    :param bool no_scheme: Remove protocol (http, tcp, etc.) type in output
    :param bool defang: Extract non-defanged IOCs
    :rtype: Iterator[:class:`str`]
    """

    unencoded_urls = itertools.chain(
        url_re(open_punc).finditer(data),
        BRACKET_URL_RE.finditer(data),
        BACKSLASH_URL_RE.finditer(data),
    )

    for url in unencoded_urls:
        if refang or defang:
            if refang:
                url = refang_data(url.group(1), no_scheme=no_scheme)

            if defang:
                url = defang_data(url.group(1))
        else:
            url = url.group(1)

        # Checks for whitespace in the string
        def found_ws(s):
            return True in [check_s in s for check_s in whitespace]

        if strip:
            if found_ws(url):
                url = re.split(WS_SYNTAX_RM, url)[0]
            else:
                url = re.split(URL_SPLIT_STR, url)[0]

        yield url


def extract_encoded_urls(
    data, refang=False, strip=False, delimiter=None, parse_json=False
):
    """
    Extract only encoded URLs!

    :param data: Input text
    :param bool refang: Refang output
    :param bool strip: Strip possible garbage from the end of URLs
    :param bool delimiter: Continue extracting even after whitespace is detected
    :param bool parse_json: Allows you to recursively parse JSON data to locate base64 strings
    :rtype: Iterator[:class:`str`]
    """

    for url in HEXENCODED_URL_RE.finditer(data):
        if refang:
            yield binascii.unhexlify(url.group(1)).decode("utf-8")
        else:
            yield url.group(1)

    for url in URLENCODED_URL_RE.finditer(data):
        if refang:
            yield unquote(url.group(1))
        else:
            yield url.group(1)

    for url in B64ENCODED_URL_RE.finditer(data):
        # Strip whitespace
        url = "".join(url.group(1).split())

        # Truncate the string if it's not a multiple of 3 bytes long
        # We don't care about the end of the string since it's probably garbage
        if len(url) % 4:
            url = url[: -(len(url) % 4)]

        if refang:
            # Decode base64
            url = base64.b64decode(url).decode("utf-8", "replace")

            # Remove the first 1-2 bytes if we got back extra leading characters from the base64
            # The only valid starts are "http" or "ftp", so look for h/f case insensitive
            url = url[re.search("[hHfF]", url).start() :]

        if delimiter:
            pass
        else:
            # Stop at the first whitespace or non-unicode character
            url = url.split("\ufffd")[0].split()[0]

        if strip:
            url = re.split(URL_SPLIT_STR, url)[0]

        yield url

    def validate_base64(b64_data):
        """
        Validate a string is Base64 encoded.

        :param b64_data: Input base64 string
        """

        try:
            if isinstance(b64_data, str):
                base64_bytes = bytes(b64_data, "ascii")
            elif isinstance(b64_data, bytes):
                base64_bytes = b64_data
            else:
                raise ValueError("Data type should be a string or bytes")

            return base64.b64encode(base64.b64decode(base64_bytes)) == base64_bytes
        except Exception:
            return False

    if parse_json:
        try:
            try:
                for json_data in json.loads(data):
                    for _, value in json_data.items():
                        if validate_base64(value):
                            yield base64.b64decode(value).decode("ascii")
            except json.decoder.JSONDecodeError:
                pass
        except AttributeError:
            pass


def extract_ips(data, refang=False):
    """
    Extract IP addresses!

    Includes both IPv4 and IPv6 addresses.

    :param data: Input text
    :param bool refang: Refang output
    :rtype: :py:func:`itertools.chain`
    """
    return itertools.chain(
        extract_ipv4s(data, refang=refang),
        extract_ipv6s(data),
    )


def extract_ipv4s(data, refang=False):
    """
    Extract IPv4 addresses!

    :param data: Input text
    :param bool refang: Refang output
    :rtype: Iterator[:class:`str`]
    """

    def ipv4_str(data):
        protocol_str = re.compile(r"https|http|ftp")

        for pro in protocol_str.finditer(data):
            if refang:
                return refang_ipv4(pro.group(0))
            else:
                return pro.group(0)

    for ip_address in ipv4_len().finditer(data):
        # Iterates over any ip address with 4 numbers after the final (3rd) octet
        for ip_address in ipv4_len(4).finditer(data):
            pass

        if refang:
            yield refang_ipv4(ip_address.group(0))
        else:
            yield ip_address.group(0)

        if ipv4_str(data) != None:
            yield ipv4_str(data)


def extract_ipv6s(data):
    """
    Extract IPv6 addresses!

    Not guaranteed to catch all valid IPv6 addresses.

    :param data: Input text
    :rtype: Iterator[:class:`str`]
    """

    for ip_address in IPV6_RE.finditer(data):
        # Sets a minimal standard for IPv6 (0:0:0:0:0:0:0:0)
        if len(data) >= 15:
            yield ip_address.group(0)


def extract_emails(data, refang=False):
    """
    Extract email addresses!

    :param data: Input text
    :param bool refang: Refang output
    :rtype: Iterator[:class:`str`]
    """

    for email in EMAIL_RE.finditer(data):
        if refang:
            email = refang_email(email.group(1))
        else:
            email = email.group(1)

        yield email


def extract_telephone_nums(data):
    """
    Extract telephone numbers!

    :param data: Input text
    :rtype: Iterator[:class:`str`]
    """

    for tele in TELEPHONE_RE.finditer(data):
        yield tele.group(1)


def extract_hashes(data):
    """
    Extract MD5/SHA hashes!

    Results are returned as an itertools.chain iterable object which lazily provides the results of the other extract_*_hashes generators.

    :param data: Input text
    :rtype: :py:func:`itertools.chain`
    """

    return itertools.chain(
        extract_md5_hashes(data),
        extract_sha1_hashes(data),
        extract_sha256_hashes(data),
        extract_sha512_hashes(data),
    )


def extract_md5_hashes(data):
    """
    Extract MD5 hashes!

    :param data: Input text
    :rtype: Iterator[:class:`str`]
    """

    for md5 in MD5_RE.finditer(data):
        yield md5.group(1)


def extract_sha1_hashes(data):
    """
    Extract SHA1 hashes!

    :param data: Input text
    :rtype: Iterator[:class:`str`]
    """

    for sha1 in SHA1_RE.finditer(data):
        yield sha1.group(1)


def extract_sha256_hashes(data):
    """
    Extract SHA256 hashes!

    :param data: Input text
    :rtype: Iterator[:class:`str`]
    """

    for sha256 in SHA256_RE.finditer(data):
        yield sha256.group(1)


def extract_sha512_hashes(data):
    """
    Extract SHA512 hashes!

    :param data: Input text
    :rtype: Iterator[:class:`str`]
    """

    for sha512 in SHA512_RE.finditer(data):
        yield sha512.group(1)


def extract_yara_rules(data):
    """
    Extract YARA rules!

    :param data: Input text
    :rtype: Iterator[:class:`str`]
    """

    for yara_rule in YARA_PARSE_RE.finditer(data):
        yield yara_rule.group(1).strip()


def extract_custom_iocs(data, regex_list):
    """
    Extract using custom regex strings!

    Need help? Check out the README: https://github.com/inquest/iocextract#custom-regex

    :param data: Input text
    :param regex_list: List of strings to treat as regex and match against data
    :rtype: Iterator[:class:`str`]
    """

    # Compile all the regex strings first, so we can error out quickly
    regex_objects = []

    for regex_string in regex_list:
        regex_objects.append(re.compile(regex_string))

    # Iterate over regex objects, running each against input data
    for regex_object in regex_objects:
        for ioc in regex_object.finditer(data):
            yield ioc.group(1)


def _is_ipv6_url(url):
    """
    URL network location is an IPv6 address, not a domain.

    :param url: String URL
    :rtype: bool
    """

    # Fix urlparse exception.
    parsed = urlparse(url)

    # Handle RFC 2732 IPv6 URLs with and without port, as well as non-RFC IPv6 URLs
    if "]:" in parsed.netloc:
        ipv6 = ":".join(parsed.netloc.split(":")[:-1])
    else:
        ipv6 = parsed.netloc

    try:
        ipaddress.IPv6Address(unicode(ipv6.replace("[", "").replace("]", "")))
    except ValueError:
        return False

    return True


def _refang_common(ioc):
    """
    Remove artifacts from common defangs!

    :param ioc: String IP/Email Address or URL netloc
    :rtype: str
    """

    return (
        ioc.replace("[dot]", ".")
        .replace("(dot)", ".")
        .replace("[.]", ".")
        .replace("(", "")
        .replace(")", "")
        .replace(",", ".")
        .replace(" ", "")
        .replace("\u30fb", ".")
    )


def refang_email(email):
    """
    Refang an email address!

    :param email: String email address
    :rtype: str
    """

    # Check for ' at ' and ' dot ' first
    email = re.sub("\W[aA][tT]\W", "@", email.lower())
    email = re.sub("\W*[dD][oO][tT]\W*", ".", email)

    # Then do other char replaces
    return (
        _refang_common(email)
        .replace("[", "")
        .replace("]", "")
        .replace("{", "")
        .replace("}", "")
    )


def refang_data(url, no_scheme=False):
    """
    Refang a URL!

    :param url: String URL
    :rtype: str
    """

    # First fix urlparse errors
    # Fix ipv6 parsing exception
    if "[." in url and "[.]" not in url:
        url = url.replace("[.", "[.]")
    if ".]" in url and "[.]" not in url:
        url = url.replace(".]", "[.]")
    if "[dot" in url and "[dot]" not in url:
        url = url.replace("[dot", "[.]")
    if "dot]" in url and "[dot]" not in url:
        url = url.replace("dot]", "[.]")
    if "[:]" in url:
        url = url.replace("[:]", ":")
    if "[/]" in url:
        url = url.replace("[/]", "/")

    # Since urlparse expects a scheme, make sure one exists
    if "//" not in url:
        if "__" in url[:8]:
            # Support http__domain and http:__domain
            if ":__" in url[:8]:
                url = url.replace(":__", "://", 1)
            else:
                url = url.replace("__", "://", 1)
        elif "\\\\" in url[:8]:
            # Support http:\\domain
            url = url.replace("\\\\", "//", 1)
        else:
            # Support no protocol
            pass

    # Refang (/), since it's not entirely in the netloc.
    url = url.replace("(/)", "/")

    # Refang some backslash-escaped characters.
    url = (
        url.replace("\.", ".")
        .replace("\(", "(")
        .replace("\[", "[")
        .replace("\)", ")")
        .replace("\]", "]")
    )

    try:
        _ = urlparse(url)
    except ValueError:
        # Last resort on ipv6 fail
        url = url.replace("[", "").replace("]", "")

    # Now use urlparse and continue processing
    parsed = urlparse(url)

    # Handle URLs with no scheme / obfuscated scheme
    # Note: ParseResult._replace is a public member, this is safe
    if parsed.scheme not in ["http", "https", "ftp"]:
        if parsed.scheme.strip("s") in ["ftx", "fxp"]:
            scheme = "ftp"
        elif HTTPS_SCHEME_DEFANG_RE.fullmatch(parsed.scheme):
            scheme = "https"
        else:
            if no_scheme:
                scheme = ""
            else:
                scheme = "http"

        parsed = parsed._replace(scheme=scheme)
        replacee = "{}:///".format(scheme)
        replacement = "{}://".format(scheme)
        url = parsed.geturl().replace(replacee, replacement)

        try:
            _ = urlparse(url)
        except ValueError:
            # Last resort on ipv6 fail
            url = url.replace("[", "").replace("]", "")

        parsed = urlparse(url)

    # Remove artifacts from common defangs
    parsed = parsed._replace(netloc=_refang_common(parsed.netloc))
    parsed = parsed._replace(path=parsed.path.replace("[.]", "."))

    # Fix example[.]com, but keep RFC 2732 URLs intact
    if not _is_ipv6_url(url):
        parsed = parsed._replace(netloc=parsed.netloc.replace("[", "").replace("]", ""))

    return parsed.geturl()


def refang_ipv4(ip_address):
    """
    Refang an IPv4 address!

    :param ip_address: String IPv4 address
    :rtype: str
    """

    return (
        _refang_common(ip_address).replace("[", "").replace("]", "").replace("\\", "")
    )


def defang_data(ioc):
    """
    Defang a URL, domain, or IPv4 address!

    :param ioc: String URL, domain, or IPv4 address
    :rtype: str
    """

    # If it's a url, defang just the scheme and netloc
    try:
        parsed = urlparse(ioc)
        if parsed.netloc:
            parsed = parsed._replace(
                netloc=parsed.netloc.replace(".", "[.]"),
                scheme=parsed.scheme.replace("t", "x"),
            )
            return parsed.geturl()
    except ValueError:
        pass

    # If it's a domain or IP, defang up to the first slash
    split_list = ioc.split("/")
    defanged = split_list[0].replace(".", "[.]")
    
    # Include everything after the first slash without modification
    if len(split_list) > 1:
        defanged = "/".join([defanged] + split_list[1:])

    return defanged


def main():
    """
    Run as a command line interface!

    Advanced Indicator of Compromise (IOC) extractor.

    If no arguments are specified, the default behavior is to extract all IOCs.
    """

    parser = argparse.ArgumentParser(
        description="""
            Advanced Indicator of Compromise (IOC) extractor.
            If no arguments are specified, the default behavior is to extract all IOCs.
        """
    )
    parser.add_argument(
        "-i",
        "--input",
        type=lambda x: io.open(x, "r", encoding="utf-8", errors="ignore"),
        default=io.open(0, "r", encoding="utf-8", errors="ignore"),
        help="default: stdin",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=lambda x: io.open(x, "w", encoding="utf-8", errors="ignore"),
        default=io.open(1, "w", encoding="utf-8", errors="ignore"),
        help="default: stdout",
    )
    parser.add_argument("-ee", "--extract-emails", action="store_true")
    parser.add_argument("-ip", "--extract-ips", action="store_true")
    parser.add_argument("-ip4", "--extract-ipv4s", action="store_true")
    parser.add_argument("-ip6", "--extract-ipv6s", action="store_true")
    parser.add_argument("-u", "--extract-urls", action="store_true")
    parser.add_argument("-y", "--extract-yara-rules", action="store_true")
    parser.add_argument("-ha", "--extract-hashes", action="store_true")
    parser.add_argument(
        "-cr",
        "--custom-regex",
        type=lambda x: io.open(x, "r", encoding="utf-8", errors="ignore"),
        metavar="REGEX_FILE",
        help="file with custom regex strings, one per line, with one capture group each",
    )
    parser.add_argument("-r", "--refang", action="store_true", help="default: no")
    parser.add_argument(
        "-su",
        "--strip-urls",
        action="store_true",
        help="remove possible garbage from the end of urls. default: no",
    )
    parser.add_argument(
        "-w",
        "--wide",
        action="store_true",
        help="preprocess input to allow wide-encoded character matches. default: no",
    )
    parser.add_argument("-j", "--json", action="store_true")
    parser.add_argument(
        "-op",
        "--open",
        action="store_true",
        help="Removes the end puncuation regex when extracting URLs",
    )
    parser.add_argument(
        "-rm",
        "--rm_scheme",
        action="store_true",
        help="Removes the protocol from the url (i.e. http, https, etc.)",
    )
    parser.add_argument(
        "-d",
        "--dir",
        action="store_true",
        help="Extract IOCs from all files within a directory",
    )
    parser.add_argument(
        "-dn", "--dirname", help="Path of the directory to extract IOCs"
    )
    parser.add_argument(
        "-ri",
        "--remote_input",
        action="store_true",
        help="Extract IOCs from a remote data source",
    )
    parser.add_argument(
        "-url", "--url", help="URL to extract IOCs from"
    )

    args = parser.parse_args()

    dir_db = []

    if args.dir:
        dir_path = Path(args.dirname).glob("**/*.txt")

        for path in dir_path:
            dir_db.append(str(path))

    if not args.dir and not args.remote_input:
        # Read user unput
        # TODO: Improve the method of data input
        data = args.input.read()

    if args.wide:
        data = data.replace("\x00", "")

    # By default, extract all.
    extract_all = not (
        args.extract_ips
        or args.extract_urls
        or args.extract_yara_rules
        or args.extract_hashes
        or args.extract_ipv4s
        or args.extract_ipv6s
        or args.extract_emails
        or args.custom_regex
    )

    memo = {}

    # Extracts IOCs from all files in a directory
    if args.dir:
        for d in dir_db:
            with open(d, "r") as f:
                data = f.read()

            if args.extract_emails or extract_all:
                memo["emails"] = list(extract_emails(data, refang=args.refang))
            if args.extract_ipv4s or args.extract_ips or extract_all:
                memo["ipv4s"] = list(extract_ipv4s(data, refang=args.refang))
            if args.extract_ipv6s or args.extract_ips or extract_all:
                memo["ipv6s"] = list(extract_ipv6s(data))
            if args.extract_urls or extract_all:
                memo["urls"] = list(extract_urls(data, refang=args.refang, strip=args.strip_urls))
            
            if args.open:
                memo["open_punc"] = list(
                    extract_urls(
                        data,
                        refang=args.refang,
                        strip=args.strip_urls,
                        open_punc=args.open,
                    )
                )
            
            if args.rm_scheme:
                memo["no_protocol"] = list(
                    extract_urls(
                        data,
                        refang=args.refang,
                        strip=args.strip_urls,
                        open_punc=args.open,
                        no_scheme=args.rm_scheme,
                    )
                )
            
            if args.extract_yara_rules or extract_all:
                memo["yara_rules"] = list(extract_yara_rules(data))
            
            if args.extract_hashes or extract_all:
                memo["hashes"] = list(extract_hashes(data))

            # Custom regex file, one per line
            if args.custom_regex:
                regex_list = [l.strip() for l in args.custom_regex.readlines()]

                try:
                    memo["custom_regex"] = list(extract_custom_iocs(data, regex_list))
                except (IndexError, re.error) as e:
                    sys.stderr.write("Error in custom regex: {e}\n".format(e=e))

            if args.json:
                ioc = json.dumps(memo, indent=4, sort_keys=True)
            else:
                ioc = "\n".join(sum(memo.values(), []))

            args.output.write("{ioc}\n".format(ioc=ioc))
            args.output.flush()

    elif args.remote_input:
        remote_url = requests.get(args.url)

        if remote_url.status_code != 200:
            args.output.write("Unable to access remote host: {0}".format(args.url))
            sys.exit(1)

        file_contents = "/tmp/{0}.txt".format("".join(random.choice(string.ascii_lowercase) for _ in range(10)))

        with open(file_contents, "w") as f:
            f.write(str(remote_url.content))

        with open(file_contents, "r") as f:
            data = f.read()

        if args.extract_emails or extract_all:
            memo["emails"] = list(extract_emails(data, refang=args.refang))
        if args.extract_ipv4s or args.extract_ips or extract_all:
            memo["ipv4s"] = list(extract_ipv4s(data, refang=args.refang))
        if args.extract_ipv6s or args.extract_ips or extract_all:
            memo["ipv6s"] = list(extract_ipv6s(data))
        if args.extract_urls or extract_all:
            memo["urls"] = list(extract_urls(data, refang=args.refang, strip=args.strip_urls))
        
        if args.open:
            memo["open_punc"] = list(
                extract_urls(
                    data,
                    refang=args.refang,
                    strip=args.strip_urls,
                    open_punc=args.open,
                )
            )
        
        if args.rm_scheme:
            memo["no_protocol"] = list(
                extract_urls(
                    data,
                    refang=args.refang,
                    strip=args.strip_urls,
                    open_punc=args.open,
                    no_scheme=args.rm_scheme,
                )
            )
        
        if args.extract_yara_rules or extract_all:
            memo["yara_rules"] = list(extract_yara_rules(data))
        
        if args.extract_hashes or extract_all:
            memo["hashes"] = list(extract_hashes(data))

        # Custom regex file, one per line
        if args.custom_regex:
            regex_list = [l.strip() for l in args.custom_regex.readlines()]

            try:
                memo["custom_regex"] = list(extract_custom_iocs(data, regex_list))
            except (IndexError, re.error) as e:
                sys.stderr.write("Error in custom regex: {e}\n".format(e=e))

        if args.json:
            ioc = json.dumps(memo, indent=4, sort_keys=True)
        else:
            ioc = "\n".join(sum(memo.values(), []))

        args.output.write("{ioc}\n".format(ioc=ioc))
        args.output.flush()

        # Cleanup temp file
        os.remove(file_contents)

    else:
        if args.extract_emails or extract_all:
            memo["emails"] = list(extract_emails(data, refang=args.refang))
        if args.extract_ipv4s or args.extract_ips or extract_all:
            memo["ipv4s"] = list(extract_ipv4s(data, refang=args.refang))
        if args.extract_ipv6s or args.extract_ips or extract_all:
            memo["ipv6s"] = list(extract_ipv6s(data))
        if args.extract_urls or extract_all:
            memo["urls"] = list(
                extract_urls(data, refang=args.refang, strip=args.strip_urls)
            )
        if args.open:
            memo["open_punc"] = list(
                extract_urls(
                    data, refang=args.refang, strip=args.strip_urls, open_punc=args.open
                )
            )
        if args.rm_scheme:
            memo["no_protocol"] = list(
                extract_urls(
                    data,
                    refang=args.refang,
                    strip=args.strip_urls,
                    open_punc=args.open,
                    no_scheme=args.rm_scheme,
                )
            )
        if args.extract_yara_rules or extract_all:
            memo["yara_rules"] = list(extract_yara_rules(data))
        if args.extract_hashes or extract_all:
            memo["hashes"] = list(extract_hashes(data))

        # Custom regex file, one per line.
        if args.custom_regex:
            regex_list = [l.strip() for l in args.custom_regex.readlines()]

            try:
                memo["custom_regex"] = list(extract_custom_iocs(data, regex_list))
            except (IndexError, re.error) as e:
                sys.stderr.write("Error in custom regex: {e}\n".format(e=e))

        if args.json:
            ioc = json.dumps(memo, indent=4, sort_keys=True)
        else:
            ioc = "\n".join(sum(memo.values(), []))

        args.output.write("{ioc}\n".format(ioc=ioc))
        args.output.flush()


if __name__ == "__main__":
    main()
