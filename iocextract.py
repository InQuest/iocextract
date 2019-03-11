"""Extract and optionallly refang Indicators of Compromise (IOCs) from text.

All methods return iterator objects, not lists. If for some reason you need
a list, do e.g.: ``list(extract_iocs(my_data))``.

Otherwise, you can iterate over the objects (e.g. in a ``for`` loop) normally.
Each object yielded from the generators will by of type :class:`str`.
"""
import io
import sys
import itertools
import argparse
import binascii
import base64

try:
    # python3
    from urllib.parse import urlparse, unquote
    unicode = str
except ImportError:
    from urlparse import urlparse
    from urllib import unquote


import ipaddress
import regex as re


# Reusable end punctuation regex.
END_PUNCTUATION = r"[\.\?>\"'\)!,}:;\u201d\u2019\uff1e\uff1c\]]*"

# Reusable regex for symbols commonly used to defang.
SEPARATOR_DEFANGS = r"[\(\)\[\]{}<>\\]"

# Split URLs on some characters that may be valid, but may also be garbage.
URL_SPLIT_STR = r"[>\"'\),};]"

# Get basic url format, including a few obfuscation techniques, main anchor is the uri scheme.
GENERIC_URL_RE = re.compile(r"""
        (
            # Scheme.
            [fhstu]\S\S?[px]s?

            # One of these delimiters/defangs.
            (?:
                :\/\/|
                :\\\\|
                :?__
            )

            # Any number of defang characters.
            (?:
                \x20|
                """ + SEPARATOR_DEFANGS + r"""
            )*

            # Domain/path characters.
            \w
            \S+?

            # CISCO ESA style defangs followed by domain/path characters.
            (?:\x20[\/\.][^\.\/\s]\S*?)*
        )
    """ + END_PUNCTUATION + r"""
        (?=\s|$)
    """, re.IGNORECASE | re.VERBOSE | re.UNICODE)

# Get some obfuscated urls, main anchor is brackets around the period.
BRACKET_URL_RE = re.compile(r"""
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
    """ + END_PUNCTUATION + r"""
        (?=\s|$)
    """, re.VERBOSE | re.UNICODE)

# Get some obfuscated urls, main anchor is backslash before a period.
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
    """ + END_PUNCTUATION + r"""
        (?=\s|$)
    """, re.VERBOSE | re.UNICODE)

# Get hex-encoded urls.
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

# Get urlencoded urls.
URLENCODED_URL_RE = re.compile(r"""
        (s?[hf]t?tps?%3A%2F%2F\w[\w%-]*?)(?:[^\w%-]|$)
    """, re.IGNORECASE | re.VERBOSE)

# Get base64-encoded urls.
B64ENCODED_URL_RE = re.compile(r"""
        (
            # b64re '([hH][tT][tT][pP][sS]|[hH][tT][tT][pP]|[fF][tT][pP])://'
            # Modified to ignore whitespace.
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
            # Up to 260 characters (pre-encoding, reasonable URL length).
            [A-Za-z0-9+/=\s]{1,357}
        )
        (?=[^A-Za-z0-9+/=\s]|$)
    """, re.VERBOSE)

# Get some valid obfuscated ip addresses.
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

# Experimental IPv6 regex, will not catch everything but should be sufficent for now.
IPV6_RE = re.compile(r"""
        \b(?:[a-f0-9]{1,4}:|:){2,7}(?:[a-f0-9]{1,4}|:)\b
    """, re.IGNORECASE | re.VERBOSE)

# Capture email addresses including common defangs.
EMAIL_RE = re.compile(r"""
        (
            [a-z0-9_.+-]+
            [\(\[{\x20]*
            (?:@|\Wat\W)
            [\)\]}\x20]*
            [a-z0-9-]+
            (?:
                (?:
                    (?:
                        \x20*
                        """ + SEPARATOR_DEFANGS + r"""
                        \x20*
                    )*
                    \.
                    (?:
                        \x20*
                        """ + SEPARATOR_DEFANGS + r"""
                        \x20*
                    )*
                    |
                    \W+dot\W+
                )
                [a-z0-9-]+?
            )+
        )
    """ + END_PUNCTUATION + r"""
        (?=\s|$)
    """, re.IGNORECASE | re.VERBOSE | re.UNICODE)

MD5_RE = re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{32})(?:[^a-fA-F\d]|\b)")
SHA1_RE = re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{40})(?:[^a-fA-F\d]|\b)")
SHA256_RE = re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{64})(?:[^a-fA-F\d]|\b)")
SHA512_RE = re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{128})(?:[^a-fA-F\d]|\b)")

# YARA regex.
YARA_PARSE_RE = re.compile(r"""
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
    :rtype: :py:func:`itertools.chain`
    """
    return itertools.chain(
        extract_unencoded_urls(data, refang=refang, strip=strip),
        extract_encoded_urls(data, refang=refang, strip=strip),
    )


def extract_unencoded_urls(data, refang=False, strip=False):
    """Extract only unencoded URLs.

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


def extract_encoded_urls(data, refang=False, strip=False):
    """Extract only encoded URLs.

    :param data: Input text
    :param bool refang: Decode output?
    :param bool strip: Strip possible garbage from the end of URLs
    :rtype: Iterator[:class:`str`]
    """
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

    for url in B64ENCODED_URL_RE.finditer(data):
        # Strip whitespace.
        url = ''.join(url.group(1).split())

        # Truncate the string if it's not a multiple of 3 bytes long.
        # We don't care about the end of the string since it's probably garbage.
        if len(url) % 4:
            url = url[:-(len(url) % 4)]

        if refang:
            # Decode base64.
            url = base64.b64decode(url).decode('utf-8', 'replace')

            # Remove the first 1-2 bytes if we got back extra leading characters from the base64.
            # The only valid starts are "http" or "ftp", so look for h/f case insensitive.
            url = url[re.search('[hHfF]', url).start():]

            # Stop at the first whitespace or non-unicode character.
            url = url.split(u'\ufffd')[0].\
                      split()[0]

        if strip:
            url = re.split(URL_SPLIT_STR, url)[0]

        yield url


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
    """Extract email addresses.

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
    for yara_rule in YARA_PARSE_RE.finditer(data):
        yield yara_rule.group(1).strip()


def extract_custom_iocs(data, regex_list):
    """Extract using custom regex strings.

    Will always yield only the first *group* match from each regex.

    Always use a single capture group! Do this::

        [
            r'(my regex)',  # This yields 'my regex' if the pattern matches.
            r'my (re)gex',  # This yields 're' if the pattern matches.
        ]

    NOT this::

        [
            r'my regex',  # BAD! This doesn't yield anything.
            r'(my) (re)gex',  # BAD! This yields 'my' if the pattern matches.
        ]

    For complicated regexes, you can combine capture and non-capture groups,
    like this::

        [
            r'(?:my|your) (re)gex',  # This yields 're' if the pattern matches.
        ]

    Note the (?: ) syntax for noncapture groups vs the ( ) syntax for the capture
    group.

    :param data: Input text
    :param regex_list: List of strings to treat as regex and match against data.
    :rtype: Iterator[:class:`str`]
    """
    # Compile all the regex strings first, so we can error out quickly.
    regex_objects = []
    for regex_string in regex_list:
        regex_objects.append(re.compile(regex_string))

    # Iterate over regex objects, running each against input data.
    for regex_object in regex_objects:
        for ioc in regex_object.finditer(data):
            yield ioc.group(1)


def _is_ipv6_url(url):
    """URL network location is an IPv6 address, not a domain.

    :param url: String URL
    :rtype: bool
    """
    # Fix urlparse exception.
    parsed = urlparse(url)

    # Handle RFC 2732 IPv6 URLs with and without port, as well as non-RFC IPv6 URLs.
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
    # Check for ' at ' and ' dot ' first.
    email = re.sub('\W[aA][tT]\W', '@', email.lower())
    email = re.sub('\W*[dD][oO][tT]\W*', '.', email)

    # Then do other char replaces.
    return _refang_common(email).replace('[', '').\
                                 replace(']', '').\
                                 replace('{', '').\
                                 replace('}', '').\
                                 replace('{', '')


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
        if '__' in url[:8]:
            # Support http__domain and http:__domain.
            if ':__' in url[:8]:
                url = url.replace(':__', '://', 1)
            else:
                url = url.replace('__', '://', 1)
        elif '\\\\' in url[:8]:
            # Support http:\\domain.
            url = url.replace('\\\\', '//', 1)
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
    parser.add_argument('--extract-emails', action='store_true')
    parser.add_argument('--extract-ips', action='store_true')
    parser.add_argument('--extract-ipv4s', action='store_true')
    parser.add_argument('--extract-ipv6s', action='store_true')
    parser.add_argument('--extract-urls', action='store_true')
    parser.add_argument('--extract-yara-rules', action='store_true')
    parser.add_argument('--extract-hashes', action='store_true')
    parser.add_argument('--custom-regex', type=lambda x: io.open(x, 'r', encoding='utf-8', errors='ignore'),
                        metavar='REGEX_FILE',
                        help="file with custom regex strings, one per line, with one capture group each")
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
    if not (args.extract_ips or args.extract_urls or args.extract_yara_rules or args.extract_hashes or
            args.extract_ipv4s or args.extract_ipv6s or args.extract_emails or args.custom_regex):
        for ioc in extract_iocs(data, refang=args.refang, strip=args.strip_urls):
            args.output.write(u"{ioc}\n".format(ioc=ioc))
    else:
        if args.extract_emails:
            for ioc in extract_emails(data, refang=args.refang):
                args.output.write(u"{ioc}\n".format(ioc=ioc))
        if args.extract_ips:
            for ioc in extract_ips(data, refang=args.refang):
                args.output.write(u"{ioc}\n".format(ioc=ioc))
        if args.extract_ipv4s:
            for ioc in extract_ipv4s(data, refang=args.refang):
                args.output.write(u"{ioc}\n".format(ioc=ioc))
        if args.extract_ipv6s:
            for ioc in extract_ipv6s(data):
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

        # Custom regex file, one per line.
        if args.custom_regex:
            regex_list = [l.strip() for l in args.custom_regex.readlines()]

            try:
                for ioc in extract_custom_iocs(data, regex_list):
                    args.output.write(u"{ioc}\n".format(ioc=ioc))
            except (IndexError, re.error) as e:
                sys.stderr.write('Error in custom regex: {e}\n'.format(e=e))


if __name__ == "__main__":
    main()
