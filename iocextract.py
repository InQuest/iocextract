"""Extract and optionallly refang Indicators of Compromise (IOCs) from text.

All methods return iterator objects, not lists. If for some reason you need
a list, do e.g.: ``list(extract_iocs(my_data))``.

Otherwise, you can iterate over the objects (e.g. in a ``for`` loop) normally.
Each object yielded from the generators will by of type :class:`str`.
"""
import io
import regex as re
import itertools
import argparse
import binascii
try:
    # python3
    from urllib.parse import urlparse, unquote
    unicode = str
except ImportError:
    from urlparse import urlparse
    from urllib import unquote

import ipaddress

# Get basic url format, including a few obfuscation techniques, main anchor is the uri scheme
GENERIC_URL_RE = re.compile(r"""
        (
            [fhstu]\w\w?[px]s?
            (?::\/\/|__)
            [\x20\(\[]*
            \w
            \S+?
            (?:\x20[\/\.][^\.\/\s]\S*?)*
        )
        [\.\?>\"'\)!,}:;\u201d\u2019\uff1e\uff1c\]]*
        (?=\s|$)
    """, re.IGNORECASE | re.VERBOSE)

# Split URLs on some characters that may be valid, but may also be garbage
URL_SPLIT_STR = r"[>\"'\),};]"

# Get some obfuscated urls, main anchor is brackets around the period
BRACKET_URL_RE = re.compile(r"""
        \b
        (
            [\:\/\\\w\[\]\(\)-]+
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
        [\.\?>\"'\)!,}:;\u201d\u2019\uff1e\uff1c\]]*
        (?=\s|$)
    """, re.VERBOSE)

# Get some obfuscated urls, main anchor is backslash before a period
BACKSLASH_URL_RE = re.compile(r"""
        \b
        (
            [\:\/\\\w\[\]\(\)-]+
            (?:
                \x20?
                \\?\.
                \x20?
                \S*?
            )*?
            (?:
                \x20?
                \\\.
                \x20?
                \S*?
            )
            (?:
                \x20?
                \\?\.
                \x20?
                \S*?
            )*
        )
        [\.\?>\"'\)!,}:;\u201d\u2019\uff1e\uff1c\]]*
        (?=\s|$)
    """, re.VERBOSE)

# Get hex-encoded urls
HEXENCODED_URL_RE = re.compile(r"""
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
    """, re.IGNORECASE | re.VERBOSE)

# Get urlencoded urls
URLENCODED_URL_RE = re.compile(r"""
        (s?[hf]t?tps?%3A%2F%2F\w[\w%-]*?)(?:[^\w%-]|$)
    """, re.IGNORECASE | re.VERBOSE)

# Get some valid obfuscated ip addresses
IPV4_RE = re.compile(r"""
        (?:^|
            (?![^\d\.])
        )
        (?:
            (?:[1-9]?\d|1\d\d|2[0-4]\d|25[0-5])
            [\[\(\\]*?\.[\]\)]*?
        ){3}
        (?:[1-9]?\d|1\d\d|2[0-4]\d|25[0-5])
        (?:(?=[^\d\.])|$)
    """, re.VERBOSE)

# Experimental IPV6 regex, will not catch everything but should be sufficent for now
IPV6_RE = re.compile(r"""
        \b(?:[a-f0-9]{1,4}:|:){2,7}(?:[a-f0-9]{1,4}|:)\b
    """, re.IGNORECASE | re.VERBOSE)

# Capture email addresses including common defangs
EMAIL_RE = re.compile(r"""
        (
            [a-zA-Z0-9_.+-]+
            \x20?@\x20?
            [a-zA-Z0-9-]+
            (?:
                (?:
                    \x20*
                    [\(\[]
                    \x20*
                )*
                \.
                (?:
                    \x20*
                    [\]\)]
                    \x20*
                )*
                [a-zA-Z0-9-]+?
            )+
        )
        [\.\?>\"'\)!,}:;\u201d\u2019\uff1e\uff1c\]]*
        (?=\s|$)
    """, re.VERBOSE)

MD5_RE = re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{32})(?:[^a-fA-F\d]|\b)")
SHA1_RE = re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{40})(?:[^a-fA-F\d]|\b)")
SHA256_RE = re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{64})(?:[^a-fA-F\d]|\b)")
SHA512_RE = re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{128})(?:[^a-fA-F\d]|\b)")

# YARA regex
YARA_SPLIT_STR = r"""
        \n[\t\s]*\}[\s\t]*(rule[\t\s][^\r\n]+(?:\{|[\r\n][\r\n\s\t]*\{))
"""

YARA_PARSE_RE = re.compile(r"""
        ^[\t\s]*
        (
            rule[\t\s][^\r\n]+
            (?:\{|[\r\n][\r\n\s\t]*\{)
            .*?condition:.*?\r?\n?[\t\s]*\}
        )
        [\s\t]*
        (?:$|\r?\n)
    """, re.MULTILINE | re.DOTALL | re.VERBOSE)


def extract_iocs(data, refang=False, strip=False):
    """Extract all IOCs.

    Results are returned as an itertools.chain iterable object which
    lazily provides the results of the other extract_* generators.

    :param data: Input text
    :param bool refang: Refang output?
    :param bool strip: Strip possible garbage from the end of URLs
    :rtype: :py:func:`itertools.chain`
    """
    return itertools.chain(
        extract_urls(data, refang=refang, strip=strip),
        extract_ips(data, refang=refang),
        extract_emails(data, refang=refang),
        extract_hashes(data),
        extract_yara_rules(data)
    )

def extract_urls(data, refang=False, strip=False):
    """Extract URLs.

    :param data: Input text
    :param bool refang: Refang output?
    :param bool strip: Strip possible garbage from the end of URLs
    :rtype: Iterator[:class:`str`]
    """
    unencoded_urls = itertools.chain(
        GENERIC_URL_RE.finditer(data),
        BRACKET_URL_RE.finditer(data),
        BACKSLASH_URL_RE.finditer(data),
    )
    for url in unencoded_urls:
        if refang:
            url = refang_url(url.group(1))
        else:
            url = url.group(1)

        if strip:
            url = re.split(URL_SPLIT_STR, url)[0]

        yield url

    for url in HEXENCODED_URL_RE.finditer(data):
        if refang:
            yield binascii.unhexlify(url.group(1)).decode('utf-8')
        else:
            yield url.group(1)

    for url in URLENCODED_URL_RE.finditer(data):
        if refang:
            yield unquote(url.group(1))
        else:
            yield url.group(1)

def extract_ips(data, refang=False):
    """Extract IP addresses.

    Includes both IPv4 and IPv6 addresses.

    :param data: Input text
    :param bool refang: Refang output?
    :rtype: :py:func:`itertools.chain`
    """
    return itertools.chain(
        extract_ipv4s(data, refang=refang),
        extract_ipv6s(data),
    )

def extract_ipv4s(data, refang=False):
    """Extract IPv4 addresses.

    :param data: Input text
    :param bool refang: Refang output?
    :rtype: Iterator[:class:`str`]
    """
    for ip_address in IPV4_RE.finditer(data):
        if refang:
            yield refang_ipv4(ip_address.group(0))
        else:
            yield ip_address.group(0)

def extract_ipv6s(data):
    """Extract IPv6 addresses.

    Not guaranteed to catch all valid IPv6 addresses.

    :param data: Input text
    :rtype: Iterator[:class:`str`]
    """
    for ip_address in IPV6_RE.finditer(data):
        yield ip_address.group(0)

def extract_emails(data, refang=False):
    """Extract email addresses

    :param data: Input text
    :param bool refang: Refang output?
    :rtype: Iterator[:class:`str`]
    """
    for email in EMAIL_RE.finditer(data):
        if refang:
            email = refang_email(email.group(1))
        else:
            email = email.group(1)

        yield email

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
        yield md5.group(1)

def extract_sha1_hashes(data):
    """Extract SHA1 hashes.

    :param data: Input text
    :rtype: Iterator[:class:`str`]
    """
    for sha1 in SHA1_RE.finditer(data):
        yield sha1.group(1)

def extract_sha256_hashes(data):
    """Extract SHA256 hashes.

    :param data: Input text
    :rtype: Iterator[:class:`str`]
    """
    for sha256 in SHA256_RE.finditer(data):
        yield sha256.group(1)

def extract_sha512_hashes(data):
    """Extract SHA512 hashes.

    :param data: Input text
    :rtype: Iterator[:class:`str`]
    """
    for sha512 in SHA512_RE.finditer(data):
        yield sha512.group(1)

def extract_yara_rules(data):
    """Extract YARA rules.

    :param data: Input text
    :rtype: Iterator[:class:`str`]
    """
    yara_rules = re.sub(YARA_SPLIT_STR, "}\r\n\\1", data,
                        re.MULTILINE | re.DOTALL | re.VERBOSE)
    for yara_rule in YARA_PARSE_RE.finditer(yara_rules):
        yield yara_rule.group(1)

def _is_ipv6_url(url):
    """URL network location is an IPv6 address, not a domain.

    :param url: String URL
    :rtype: bool
    """
    # fix urlparse exception
    parsed = urlparse(url)

    # Handle RFC 2732 IPv6 URLs with and without port, as well as non-RFC IPv6 URLs
    if ']:' in parsed.netloc:
        ipv6 = ':'.join(parsed.netloc.split(':')[:-1])
    else:
        ipv6 = parsed.netloc

    try:
        ipaddress.IPv6Address(unicode(ipv6.replace('[', '').replace(']', '')))
    except ValueError:
        return False

    return True

def _refang_common(ioc):
    """Remove artifacts from common defangs.

    :param ioc: String IP/Email Address or URL netloc.
    :rtype: str
    """
    return ioc.replace('[dot]', '.').\
               replace('(dot)', '.').\
               replace('[.]', '.').\
               replace('(', '').\
               replace(')', '').\
               replace(',', '.').\
               replace(' ', '').\
               replace(u'\u30fb', '.')

def refang_email(email):
    """Refang an email address.

    :param email: String email address.
    :rtype: str
    """
    return _refang_common(email).replace('[', '').\
                                 replace(']', '')

def refang_url(url):
    """Refang a URL.

    :param url: String URL
    :rtype: str
    """
    # First fix urlparse errors.
    # Fix ipv6 parsing exception.
    if '[.' in url and '[.]' not in url:
        url = url.replace('[.', '[.]')
    if '.]' in url and '[.]' not in url:
        url = url.replace('.]', '[.]')
    if '[dot' in url and '[dot]' not in url:
        url = url.replace('[dot', '[.]')
    if 'dot]' in url and '[dot]' not in url:
        url = url.replace('dot]', '[.]')
    if '[/]' in url:
        url = url.replace('[/]', '/')

    # Since urlparse expects a scheme, make sure one exists.
    if '//' not in url:
        if '__' in url[:7]:
            # Support http__domain.
            url = url.replace('__', '://', 1)
        else:
            # Support no-protocol.
            url = 'http://' + url

    # Refang (/), since it's not entirely in the netloc.
    url = url.replace('(/)', '/')

    # Refang some backslash-escaped characters.
    url = url.replace('\.', '.').\
              replace('\(', '(').\
              replace('\[', '[').\
              replace('\)', ')').\
              replace('\]', ']')

    try:
        _ = urlparse(url)
    except ValueError:
        # Last resort on ipv6 fail.
        url = url.replace('[', '').replace(']', '')

    # Now use urlparse and continue processing.
    parsed = urlparse(url)

    # Handle URLs with no scheme / obfuscated scheme.
    # Note: ParseResult._replace is a public member, this is safe.
    if parsed.scheme not in ['http', 'https', 'ftp']:
        if parsed.scheme.strip('s') in ['ftx', 'fxp']:
            parsed = parsed._replace(scheme='ftp')
            url = parsed.geturl().replace('ftp:///', 'ftp://')
        else:
            parsed = parsed._replace(scheme='http')
            url = parsed.geturl().replace('http:///', 'http://')

        try:
            _ = urlparse(url)
        except ValueError:
            # Last resort on ipv6 fail.
            url = url.replace('[', '').replace(']', '')

        parsed = urlparse(url)

    # Remove artifacts from common defangs.
    parsed = parsed._replace(netloc=_refang_common(parsed.netloc))
    parsed = parsed._replace(path=parsed.path.replace('[.]', '.'))

    # Fix example[.]com, but keep RFC 2732 URLs intact.
    if not _is_ipv6_url(url):
        parsed = parsed._replace(netloc=parsed.netloc.replace('[', '').replace(']', ''))

    return parsed.geturl()

def refang_ipv4(ip_address):
    """Refang an IPv4 address.

    :param ip_address: String IPv4 address.
    :rtype: str
    """
    return _refang_common(ip_address).replace('[', '').\
                                      replace(']', '').\
                                      replace('\\', '')

def defang(ioc):
    """Defang a URL, domain, or IPv4 address.

    :param ioc: String URL, domain, or IPv4 address.
    :rtype: str
    """
    # If it's a url, defang just the scheme and netloc.
    try:
        parsed = urlparse(ioc)
        if parsed.netloc:
            parsed = parsed._replace(netloc=parsed.netloc.replace('.', '[.]'),
                                     scheme=parsed.scheme.replace('t', 'x'))
            return parsed.geturl()
    except ValueError:
        pass

    # If it's a domain or IP, defang up to the first slash.
    split_list = ioc.split('/')
    defanged = split_list[0].replace('.', '[.]')
    # Include everything after the first slash without modification.
    if len(split_list) > 1:
        defanged = '/'.join([defanged] + split_list[1:])

    return defanged

def main():
    """Run as a commandline utility."""
    parser = argparse.ArgumentParser(
        description="""Advanced Indicator of Compromise (IOC) extractor.
                       If no arguments are specified, the default behavior is
                       to extract all IOCs.""")
    parser.add_argument('--input', type=lambda x: io.open(x, 'r', encoding='utf-8', errors='ignore'),
                        default=io.open(0, 'r', encoding='utf-8', errors='ignore'), help="default: stdin")
    parser.add_argument('--output', type=lambda x: io.open(x, 'w', encoding='utf-8', errors='ignore'),
                        default=io.open(1, 'w', encoding='utf-8', errors='ignore'), help="default: stdout")
    parser.add_argument('--extract-ips', action='store_true')
    parser.add_argument('--extract-urls', action='store_true')
    parser.add_argument('--extract-yara-rules', action='store_true')
    parser.add_argument('--extract-hashes', action='store_true')
    parser.add_argument('--refang', action='store_true', help="default: no")
    parser.add_argument('--strip-urls', action='store_true',
                        help="remove possible garbage from the end of urls. default: no")
    parser.add_argument('--wide', action='store_true',
                        help="preprocess input to allow wide-encoded character matches. default: no")
    args = parser.parse_args()

    # Read input.
    data = args.input.read()
    if args.wide:
        data = data.replace('\x00', '')

    # By default, extract all.
    if not (args.extract_ips or args.extract_urls or args.extract_yara_rules or args.extract_hashes):
        for ioc in extract_iocs(data, refang=args.refang, strip=args.strip_urls):
            args.output.write(u"{ioc}\n".format(ioc=ioc))
    else:
        if args.extract_ips:
            for ioc in extract_ips(data, refang=args.refang):
                args.output.write(u"{ioc}\n".format(ioc=ioc))
        if args.extract_urls:
            for ioc in extract_urls(data, refang=args.refang, strip=args.strip_urls):
                args.output.write(u"{ioc}\n".format(ioc=ioc))
        if args.extract_yara_rules:
            for ioc in extract_yara_rules(data):
                args.output.write(u"{ioc}\n".format(ioc=ioc))
        if args.extract_hashes:
            for ioc in extract_hashes(data):
                args.output.write(u"{ioc}\n".format(ioc=ioc))

if __name__ == "__main__":
    main()
