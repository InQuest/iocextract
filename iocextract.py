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


def experimental_regex_patterns():
    # Experimental REGEX sources, available for direct use as a dict -> list
    # This dictionary provides a place to test new REGEX patterns
    # Extraction regexes, in narrow/big-endian/little-endian format
    IOC_REGEX_SOURCES = {
        # domain names
        "domain": [
            "(?:^|[^\\w]|['\"])(([a-z0-9\\-]{4,}\\[?\\.\\]?)+(abogado|ac|academy|accountants|active|actor|ad|adult|ae|aero|af|ag|agency|ai|airforce|al|allfinanz|alsace|am|amsterdam|an|android|ao|aq|aquarelle|ar|archi|army|arpa|asia|associates|at|attorney|au|auction|audio|autos|aw|ax|axa|az|ba|band|bank|bar|barclaycard|barclays|bargains|bayern|bb|bd|be|beer|berlin|best|bf|bg|bh|bi|bid|bike|bingo|bio|biz|bj|black|blackfriday|bloomberg|blue|bm|bmw|bn|bnpparibas|bo|boo|boutique|br|brussels|bs|bt|budapest|build|builders|business|buzz|bv|bw|by|bz|bzh|cal|camera|camp|cancerresearch|canon|capetown|capital|caravan|cards|care|career|careers|cartier|casa|cash|cat|catering|cc|cd|center|ceo|cern|cf|cg|ch|channel|chat|cheap|christmas|chrome|church|ci|citic|city|ck|cl|claims|cleaning|click|clinic|clothing|club|cm|cn|co|coach|codes|coffee|college|cologne|com|community|company|computer|condos|construction|consulting|contractors|cooking|cool|coop|country|cr|credit|creditcard|cricket|crs|cruises|cu|cuisinella|cv|cw|cx|cy|cymru|cz|dabur|dad|dance|dating|day|dclk|de|deals|degree|delivery|democrat|dental|dentist|desi|design|dev|diamonds|diet|digital|direct|directory|discount|dj|dk|dm|dnp|do|docs|domains|doosan|durban|dvag|dz|eat|ec|edu|education|ee|eg|email|emerck|energy|engineer|engineering|enterprises|equipment|er|es|esq|estate|et|eu|eurovision|eus|events|everbank|exchange|expert|exposed|fail|farm|fashion|feedback|fi|finance|financial|firmdale|fish|fishing|fit|fitness|fj|fk|flights|florist|flowers|flsmidth|fly|fo|foo|forsale|foundation|fr|frl|frogans|fund|furniture|futbol|ga|gal|gallery|garden|gb|gbiz|gd|ge|gent|gf|gg|ggee|gh|gi|gift|gifts|gives|gl|glass|gle|global|globo|gm|gmail|gmo|gmx|gn|goog|google|gop|gov|gp|gq|gr|graphics|gratis|green|gripe|gs|gt|gu|guide|guitars|guru|gw|gy|hamburg|hangout|haus|healthcare|help|here|hermes|hiphop|hiv|hk|hm|hn|holdings|holiday|homes|horse|host|hosting|house|how|hr|ht|hu|ibm|ie|ifm|il|im|immo|immobilien|industries|info|ing|ink|institute|insure|int|international|investments|io|iq|ir|irish|iwc|jcb|je|jetzt|jm|jo|jobs|joburg|jp|juegos|kaufen|kddi|ke|kg|kh|ki|kim|kitchen|kiwi|km|kn|koeln|kp|kr|krd|kred|kw|ky|kyoto|kz|lacaixa|land|lat|latrobe|lawyer|lb|lc|lds|lease|legal|lgbt|li|lidl|life|lighting|limited|limo|link|lk|loans|london|lotte|lotto|lr|ls|lt|ltda|lu|luxe|luxury|lv|ly|ma|madrid|maison|management|mango|market|marketing|marriott|mc|md|me|media|meet|melbourne|meme|memorial|menu|mg|mh|miami|mil|mini|mk|ml|mm|mn|mo|mobi|moda|moe|monash|money|mormon|mortgage|moscow|motorcycles|mov|mp|mq|mr|ms|mt|mu|museum|mv|mw|mx|my|mz|na|nagoya|navy|nc|ne|net|network|neustar|new|nexus|nf|ng|ngo|nhk|ni|ninja|nl|no|np|nr|nra|nrw|ntt|nu|nyc|nz|okinawa|om|one|ong|onl|ooo|org|organic|osaka|otsuka|ovh|pa|paris|partners|parts|party|pe|pf|pg|ph|pharmacy|photo|photography|photos|physio|pics|pictures|pink|pizza|pk|pl|place|plumbing|pm|pn|pohl|poker|porn|post|pr|praxi|press|pro|prod|productions|prof|properties|property|ps|pt|pub|pw|qa|qpon|quebec|re|realtor|recipes|red|rehab|reise|reisen|reit|ren|rentals|repair|report|republican|rest|restaurant|reviews|rich|rio|rip|ro|rocks|rodeo|rs|rsvp|ru|ruhr|rw|ryukyu|sa|saarland|sale|samsung|sarl|sb|sc|sca|scb|schmidt|schule|schwarz|science|scot|sd|se|services|sew|sexy|sg|sh|shiksha|shoes|shriram|si|singles|sj|sk|sky|sl|sm|sn|so|social|software|sohu|solar|solutions|soy|space|spiegel|sr|st|su|supplies|supply|support|surf|surgery|suzuki|sv|sx|sy|sydney|systems|sz|taipei|tatar|tattoo|tax|tc|td|technology|tel|temasek|tennis|tf|tg|th|tienda|tips|tires|tirol|tj|tk|tl|tm|tn|to|today|tokyo|tools|top|toshiba|town|toys|tp|tr|trade|training|travel|trust|tt|tui|tv|tw|tz|ua|ug|uk|university|uno|uol|us|uy|uz|va|vacations|vc|ve|vegas|ventures|versicherung|vet|vg|vi|viajes|video|villas|vision|vlaanderen|vn|vodka|vote|voting|voto|voyage|vu|wales|wang|watch|webcam|website|wed|wedding|wf|whoswho|wien|wiki|williamhill|wme|work|works|world|wtc|wtf|xyz|yachts|yandex|ye|yoga|yokohama|youtube|yt|za|zm|zone|zuerich|zw))(?:[^\\w]|['\"]|$)",
            "(?:\\x00\\W|^|\\x00[\\x22\\x27])((?:((?:\\x00[\\x2d0-9a-z]){4,}(?:\\x00\\x5b)?\\x00\\x2e(?:\\x00\\x5d)?))+((?:\\x00s\\x00e|\\x00g\\x00b|\\x00m\\x00i\\x00l|\\x00t\\x00a\\x00t\\x00t\\x00o\\x00o|\\x00m\\x00a\\x00n\\x00a\\x00g\\x00e\\x00m\\x00e\\x00n\\x00t|\\x00g\\x00d|\\x00h\\x00e\\x00r\\x00e|\\x00k\\x00i|\\x00t\\x00m|\\x00s\\x00y|\\x00g\\x00n|\\x00b\\x00f|\\x00m\\x00i\\x00a\\x00m\\x00i|\\x00p\\x00i\\x00c\\x00s|\\x00t\\x00k|\\x00f\\x00l\\x00i\\x00g\\x00h\\x00t\\x00s|\\x00l\\x00a|\\x00b\\x00i\\x00n\\x00g\\x00o|\\x00b\\x00h|\\x00l\\x00o\\x00n\\x00d\\x00o\\x00n|\\x00d\\x00o\\x00o\\x00s\\x00a\\x00n|\\x00a\\x00z|\\x00s\\x00u\\x00z\\x00u\\x00k\\x00i|\\x00w\\x00e\\x00b\\x00c\\x00a\\x00m|\\x00i\\x00w\\x00c|\\x00e\\x00q\\x00u\\x00i\\x00p\\x00m\\x00e\\x00n\\x00t|\\x00s\\x00y\\x00s\\x00t\\x00e\\x00m\\x00s|\\x00b\\x00r|\\x00m\\x00e\\x00m\\x00e|\\x00m\\x00o\\x00r\\x00t\\x00g\\x00a\\x00g\\x00e|\\x00s\\x00i\\x00n\\x00g\\x00l\\x00e\\x00s|\\x00t\\x00a\\x00i\\x00p\\x00e\\x00i|\\x00f\\x00i\\x00t|\\x00f\\x00o\\x00r\\x00s\\x00a\\x00l\\x00e|\\x00b\\x00t|\\x00i\\x00n\\x00s\\x00t\\x00i\\x00t\\x00u\\x00t\\x00e|\\x00c\\x00i\\x00t\\x00i\\x00c|\\x00l\\x00i\\x00m\\x00i\\x00t\\x00e\\x00d|\\x00u\\x00y|\\x00e\\x00m\\x00e\\x00r\\x00c\\x00k|\\x00v\\x00g|\\x00v\\x00i\\x00d\\x00e\\x00o|\\x00v\\x00a|\\x00p\\x00a\\x00r\\x00t\\x00s|\\x00u\\x00n\\x00i\\x00v\\x00e\\x00r\\x00s\\x00i\\x00t\\x00y|\\x00b\\x00l\\x00o\\x00o\\x00m\\x00b\\x00e\\x00r\\x00g|\\x00p\\x00i\\x00c\\x00t\\x00u\\x00r\\x00e\\x00s|\\x00c\\x00z|\\x00t\\x00e\\x00c\\x00h\\x00n\\x00o\\x00l\\x00o\\x00g\\x00y|\\x00p\\x00o\\x00h\\x00l|\\x00v\\x00u|\\x00e\\x00s\\x00q|\\x00m\\x00o\\x00b\\x00i|\\x00g\\x00l\\x00o\\x00b\\x00o|\\x00m\\x00o\\x00e|\\x00m\\x00p|\\x00g\\x00r\\x00i\\x00p\\x00e|\\x00m\\x00v|\\x00r\\x00e\\x00i\\x00s\\x00e\\x00n|\\x00a\\x00l\\x00l\\x00f\\x00i\\x00n\\x00a\\x00n\\x00z|\\x00c\\x00n|\\x00g\\x00a\\x00l\\x00l\\x00e\\x00r\\x00y|\\x00c\\x00h|\\x00c\\x00o\\x00f\\x00f\\x00e\\x00e|\\x00o\\x00n\\x00e|\\x00d\\x00a\\x00t\\x00i\\x00n\\x00g|\\x00m\\x00h|\\x00f\\x00i\\x00r\\x00m\\x00d\\x00a\\x00l\\x00e|\\x00h\\x00o\\x00s\\x00t\\x00i\\x00n\\x00g|\\x00m\\x00n|\\x00s\\x00c\\x00b|\\x00s\\x00h\\x00o\\x00e\\x00s|\\x00i\\x00r\\x00i\\x00s\\x00h|\\x00p\\x00k|\\x00l\\x00u\\x00x\\x00e|\\x00i\\x00n\\x00v\\x00e\\x00s\\x00t\\x00m\\x00e\\x00n\\x00t\\x00s|\\x00e\\x00r|\\x00h\\x00r|\\x00p\\x00a|\\x00n\\x00r|\\x00t\\x00i\\x00e\\x00n\\x00d\\x00a|\\x00m\\x00o\\x00t\\x00o\\x00r\\x00c\\x00y\\x00c\\x00l\\x00e\\x00s|\\x00p\\x00g|\\x00e\\x00d\\x00u\\x00c\\x00a\\x00t\\x00i\\x00o\\x00n|\\x00o\\x00r\\x00g\\x00a\\x00n\\x00i\\x00c|\\x00m\\x00e\\x00d\\x00i\\x00a|\\x00f\\x00l\\x00o\\x00r\\x00i\\x00s\\x00t|\\x00s\\x00u\\x00r\\x00g\\x00e\\x00r\\x00y|\\x00w\\x00f|\\x00r\\x00s|\\x00g\\x00g\\x00e\\x00e|\\x00b\\x00o\\x00u\\x00t\\x00i\\x00q\\x00u\\x00e|\\x00r\\x00u|\\x00d\\x00i\\x00r\\x00e\\x00c\\x00t\\x00o\\x00r\\x00y|\\x00g\\x00m\\x00a\\x00i\\x00l|\\x00d\\x00e\\x00a\\x00l\\x00s|\\x00i\\x00n\\x00k|\\x00d\\x00e\\x00s\\x00i|\\x00u\\x00o\\x00l|\\x00a\\x00x\\x00a|\\x00v\\x00i\\x00s\\x00i\\x00o\\x00n|\\x00t\\x00o\\x00p|\\x00c\\x00o\\x00m\\x00p\\x00a\\x00n\\x00y|\\x00f\\x00o\\x00o|\\x00i\\x00n|\\x00b\\x00a\\x00r\\x00c\\x00l\\x00a\\x00y\\x00c\\x00a\\x00r\\x00d|\\x00r\\x00e\\x00p\\x00o\\x00r\\x00t|\\x00i\\x00d|\\x00l\\x00e\\x00g\\x00a\\x00l|\\x00w\\x00e\\x00d\\x00d\\x00i\\x00n\\x00g|\\x00c\\x00a\\x00r\\x00d\\x00s|\\x00h\\x00o\\x00r\\x00s\\x00e|\\x00o\\x00s\\x00a\\x00k\\x00a|\\x00j\\x00p|\\x00d\\x00e\\x00n\\x00t\\x00a\\x00l|\\x00g\\x00l\\x00a\\x00s\\x00s|\\x00g\\x00s|\\x00k\\x00p|\\x00i\\x00m\\x00m\\x00o|\\x00t\\x00r\\x00u\\x00s\\x00t|\\x00v\\x00o\\x00t\\x00i\\x00n\\x00g|\\x00g\\x00u|\\x00k\\x00z|\\x00f\\x00m|\\x00a\\x00g|\\x00s\\x00o\\x00f\\x00t\\x00w\\x00a\\x00r\\x00e|\\x00s\\x00j|\\x00o\\x00v\\x00h|\\x00a\\x00m|\\x00g\\x00m\\x00x|\\x00v\\x00o\\x00t\\x00o|\\x00s\\x00d|\\x00g\\x00a|\\x00k\\x00n|\\x00o\\x00r\\x00g|\\x00k\\x00h|\\x00a\\x00q|\\x00t\\x00n|\\x00n\\x00y\\x00c|\\x00s\\x00x|\\x00g\\x00m|\\x00b\\x00g|\\x00o\\x00o\\x00o|\\x00t\\x00d|\\x00a\\x00r\\x00m\\x00y|\\x00l\\x00b|\\x00s\\x00r|\\x00q\\x00p\\x00o\\x00n|\\x00b\\x00i|\\x00t\\x00e\\x00m\\x00a\\x00s\\x00e\\x00k|\\x00m\\x00o\\x00r\\x00m\\x00o\\x00n|\\x00c\\x00o\\x00m\\x00p\\x00u\\x00t\\x00e\\x00r|\\x00p\\x00h\\x00y\\x00s\\x00i\\x00o|\\x00b\\x00s|\\x00y\\x00a\\x00c\\x00h\\x00t\\x00s|\\x00t\\x00o\\x00o\\x00l\\x00s|\\x00h\\x00o\\x00m\\x00e\\x00s|\\x00s\\x00y\\x00d\\x00n\\x00e\\x00y|\\x00r\\x00o\\x00c\\x00k\\x00s|\\x00g\\x00i\\x00f\\x00t|\\x00l\\x00a\\x00t\\x00r\\x00o\\x00b\\x00e|\\x00f\\x00i\\x00t\\x00n\\x00e\\x00s\\x00s|\\x00r\\x00e\\x00n\\x00t\\x00a\\x00l\\x00s|\\x00r\\x00e\\x00p\\x00a\\x00i\\x00r|\\x00t\\x00v|\\x00w\\x00t\\x00f|\\x00d\\x00i\\x00a\\x00m\\x00o\\x00n\\x00d\\x00s|\\x00v\\x00o\\x00y\\x00a\\x00g\\x00e|\\x00c\\x00o\\x00o\\x00p|\\x00n\\x00r\\x00w|\\x00n\\x00e\\x00u\\x00s\\x00t\\x00a\\x00r|\\x00c\\x00h\\x00a\\x00n\\x00n\\x00e\\x00l|\\x00v\\x00n|\\x00l\\x00d\\x00s|\\x00h\\x00o\\x00l\\x00d\\x00i\\x00n\\x00g\\x00s|\\x00l\\x00i\\x00g\\x00h\\x00t\\x00i\\x00n\\x00g|\\x00c\\x00y|\\x00d\\x00i\\x00r\\x00e\\x00c\\x00t|\\x00c\\x00h\\x00r\\x00i\\x00s\\x00t\\x00m\\x00a\\x00s|\\x00d\\x00c\\x00l\\x00k|\\x00f\\x00i\\x00s\\x00h|\\x00m\\x00s|\\x00n\\x00i\\x00n\\x00j\\x00a|\\x00b\\x00e\\x00r\\x00l\\x00i\\x00n|\\x00c\\x00h\\x00a\\x00t|\\x00g\\x00u\\x00i\\x00d\\x00e|\\x00m\\x00y|\\x00s\\x00c\\x00h\\x00u\\x00l\\x00e|\\x00c\\x00m|\\x00c\\x00g|\\x00e\\x00d\\x00u|\\x00m\\x00e|\\x00i\\x00n\\x00t\\x00e\\x00r\\x00n\\x00a\\x00t\\x00i\\x00o\\x00n\\x00a\\x00l|\\x00l\\x00e\\x00a\\x00s\\x00e|\\x00c\\x00a|\\x00h\\x00e\\x00a\\x00l\\x00t\\x00h\\x00c\\x00a\\x00r\\x00e|\\x00m\\x00e\\x00m\\x00o\\x00r\\x00i\\x00a\\x00l|\\x00m\\x00k|\\x00j\\x00e\\x00t\\x00z\\x00t|\\x00d\\x00n\\x00p|\\x00y\\x00o\\x00u\\x00t\\x00u\\x00b\\x00e|\\x00n\\x00e|\\x00v\\x00o\\x00d\\x00k\\x00a|\\x00j\\x00o\\x00b\\x00s|\\x00g\\x00r\\x00e\\x00e\\x00n|\\x00h\\x00m|\\x00p\\x00l|\\x00e\\x00u|\\x00c\\x00a\\x00n\\x00o\\x00n|\\x00k\\x00i\\x00w\\x00i|\\x00r\\x00e\\x00h\\x00a\\x00b|\\x00i\\x00n\\x00g|\\x00j\\x00o\\x00b\\x00u\\x00r\\x00g|\\x00r\\x00i\\x00c\\x00h|\\x00m\\x00a\\x00i\\x00s\\x00o\\x00n|\\x00a\\x00t\\x00t\\x00o\\x00r\\x00n\\x00e\\x00y|\\x00e\\x00g|\\x00b\\x00u\\x00i\\x00l\\x00d|\\x00e\\x00x\\x00c\\x00h\\x00a\\x00n\\x00g\\x00e|\\x00p\\x00u\\x00b|\\x00h\\x00e\\x00r\\x00m\\x00e\\x00s|\\x00d\\x00o\\x00m\\x00a\\x00i\\x00n\\x00s|\\x00c\\x00o\\x00a\\x00c\\x00h|\\x00r\\x00e\\x00s\\x00t|\\x00c\\x00o\\x00m|\\x00a\\x00r\\x00p\\x00a|\\x00n\\x00e\\x00t\\x00w\\x00o\\x00r\\x00k|\\x00i\\x00s|\\x00v\\x00i\\x00a\\x00j\\x00e\\x00s|\\x00a\\x00c\\x00t\\x00i\\x00v\\x00e|\\x00h\\x00o\\x00s\\x00t|\\x00p\\x00i\\x00z\\x00z\\x00a|\\x00d\\x00i\\x00g\\x00i\\x00t\\x00a\\x00l|\\x00a\\x00c\\x00a\\x00d\\x00e\\x00m\\x00y|\\x00b\\x00u\\x00z\\x00z|\\x00c\\x00r\\x00u\\x00i\\x00s\\x00e\\x00s|\\x00c\\x00o\\x00o\\x00l|\\x00f\\x00r|\\x00n\\x00t\\x00t|\\x00g\\x00i\\x00f\\x00t\\x00s|\\x00t\\x00u\\x00i|\\x00j\\x00m|\\x00p\\x00a\\x00r\\x00i\\x00s|\\x00r\\x00e\\x00i\\x00t|\\x00g\\x00r|\\x00n\\x00a\\x00g\\x00o\\x00y\\x00a|\\x00s\\x00c\\x00a|\\x00r\\x00e\\x00d|\\x00s\\x00o|\\x00g\\x00t|\\x00k\\x00e|\\x00k\\x00y|\\x00c\\x00o\\x00o\\x00k\\x00i\\x00n\\x00g|\\x00a\\x00f|\\x00f\\x00j|\\x00i\\x00n\\x00f\\x00o|\\x00r\\x00u\\x00h\\x00r|\\x00s\\x00i|\\x00p\\x00r\\x00o\\x00f|\\x00a\\x00l|\\x00s\\x00c|\\x00k\\x00m|\\x00w\\x00a\\x00n\\x00g|\\x00v\\x00l\\x00a\\x00a\\x00n\\x00d\\x00e\\x00r\\x00e\\x00n|\\x00b\\x00b|\\x00t\\x00o|\\x00e\\x00s\\x00t\\x00a\\x00t\\x00e|\\x00g\\x00l|\\x00b\\x00d|\\x00l\\x00c|\\x00b\\x00n|\\x00p\\x00o\\x00r\\x00n|\\x00i\\x00n\\x00t|\\x00f\\x00i\\x00n\\x00a\\x00n\\x00c\\x00e|\\x00t\\x00c|\\x00l\\x00i|\\x00f\\x00a\\x00r\\x00m|\\x00b\\x00z|\\x00b\\x00z\\x00h|\\x00b\\x00u\\x00s\\x00i\\x00n\\x00e\\x00s\\x00s|\\x00c\\x00o\\x00l\\x00l\\x00e\\x00g\\x00e|\\x00g\\x00o\\x00p|\\x00c\\x00e\\x00n\\x00t\\x00e\\x00r|\\x00p\\x00l\\x00u\\x00m\\x00b\\x00i\\x00n\\x00g|\\x00t\\x00w|\\x00y\\x00t|\\x00c\\x00a\\x00r\\x00e|\\x00v\\x00e|\\x00h\\x00e\\x00l\\x00p|\\x00s\\x00o\\x00l\\x00u\\x00t\\x00i\\x00o\\x00n\\x00s|\\x00d\\x00i\\x00e\\x00t|\\x00l\\x00g\\x00b\\x00t|\\x00s\\x00a\\x00l\\x00e|\\x00r\\x00i\\x00o|\\x00v\\x00i|\\x00g\\x00b\\x00i\\x00z|\\x00a\\x00g\\x00e\\x00n\\x00c\\x00y|\\x00c\\x00x|\\x00m\\x00r|\\x00n\\x00h\\x00k|\\x00c\\x00r|\\x00m\\x00x|\\x00c\\x00a\\x00s\\x00h|\\x00f\\x00e\\x00e\\x00d\\x00b\\x00a\\x00c\\x00k|\\x00c\\x00l|\\x00a\\x00s\\x00i\\x00a|\\x00j\\x00c\\x00b|\\x00s\\x00u\\x00p\\x00p\\x00l\\x00i\\x00e\\x00s|\\x00c\\x00f|\\x00p\\x00o\\x00k\\x00e\\x00r|\\x00m\\x00d|\\x00c\\x00a\\x00r\\x00e\\x00e\\x00r|\\x00f\\x00u\\x00n\\x00d|\\x00z\\x00o\\x00n\\x00e|\\x00p\\x00w|\\x00d\\x00j|\\x00z\\x00a|\\x00b\\x00o\\x00o|\\x00a\\x00s\\x00s\\x00o\\x00c\\x00i\\x00a\\x00t\\x00e\\x00s|\\x00b\\x00n\\x00p\\x00p\\x00a\\x00r\\x00i\\x00b\\x00a\\x00s|\\x00h\\x00n|\\x00f\\x00i\\x00s\\x00h\\x00i\\x00n\\x00g|\\x00p\\x00m|\\x00p\\x00r\\x00o|\\x00l\\x00o\\x00a\\x00n\\x00s|\\x00e\\x00t|\\x00h\\x00t|\\x00e\\x00v\\x00e\\x00n\\x00t\\x00s|\\x00r\\x00i\\x00p|\\x00n\\x00p|\\x00c\\x00l\\x00i\\x00n\\x00i\\x00c|\\x00c\\x00l\\x00e\\x00a\\x00n\\x00i\\x00n\\x00g|\\x00z\\x00w|\\x00w\\x00i\\x00k\\x00i|\\x00k\\x00a\\x00u\\x00f\\x00e\\x00n|\\x00p\\x00h\\x00o\\x00t\\x00o\\x00g\\x00r\\x00a\\x00p\\x00h\\x00y|\\x00c\\x00h\\x00e\\x00a\\x00p|\\x00l\\x00i\\x00d\\x00l|\\x00c\\x00o\\x00l\\x00o\\x00g\\x00n\\x00e|\\x00r\\x00e\\x00a\\x00l\\x00t\\x00o\\x00r|\\x00a\\x00l\\x00s\\x00a\\x00c\\x00e|\\x00h\\x00i\\x00v|\\x00t\\x00i\\x00p\\x00s|\\x00d\\x00o\\x00c\\x00s|\\x00i\\x00t|\\x00y\\x00o\\x00g\\x00a|\\x00i\\x00r|\\x00m\\x00a\\x00d\\x00r\\x00i\\x00d|\\x00d\\x00e\\x00v|\\x00s\\x00o\\x00y|\\x00i\\x00f\\x00m|\\x00k\\x00r\\x00e\\x00d|\\x00l\\x00u\\x00x\\x00u\\x00r\\x00y|\\x00k\\x00d\\x00d\\x00i|\\x00d\\x00i\\x00s\\x00c\\x00o\\x00u\\x00n\\x00t|\\x00r\\x00e\\x00s\\x00t\\x00a\\x00u\\x00r\\x00a\\x00n\\x00t|\\x00f\\x00o\\x00u\\x00n\\x00d\\x00a\\x00t\\x00i\\x00o\\x00n|\\x00b\\x00l\\x00a\\x00c\\x00k\\x00f\\x00r\\x00i\\x00d\\x00a\\x00y|\\x00n\\x00e\\x00x\\x00u\\x00s|\\x00e\\x00n\\x00g\\x00i\\x00n\\x00e\\x00e\\x00r|\\x00b\\x00u\\x00d\\x00a\\x00p\\x00e\\x00s\\x00t|\\x00c\\x00l\\x00u\\x00b|\\x00s\\x00h\\x00r\\x00i\\x00r\\x00a\\x00m|\\x00w\\x00t\\x00c|\\x00g\\x00i\\x00v\\x00e\\x00s|\\x00l\\x00o\\x00t\\x00t\\x00o|\\x00n\\x00a\\x00v\\x00y|\\x00g\\x00q|\\x00b\\x00a\\x00y\\x00e\\x00r\\x00n|\\x00c\\x00a\\x00t\\x00e\\x00r\\x00i\\x00n\\x00g|\\x00s\\x00n|\\x00w\\x00a\\x00l\\x00e\\x00s|\\x00f\\x00k|\\x00l\\x00t|\\x00s\\x00h|\\x00a\\x00o|\\x00b\\x00a\\x00r\\x00g\\x00a\\x00i\\x00n\\x00s|\\x00l\\x00r|\\x00s\\x00b|\\x00g\\x00e\\x00n\\x00t|\\x00g\\x00g|\\x00c\\x00l\\x00i\\x00c\\x00k|\\x00a\\x00u|\\x00h\\x00o\\x00u\\x00s\\x00e|\\x00g\\x00i|\\x00e\\x00n\\x00t\\x00e\\x00r\\x00p\\x00r\\x00i\\x00s\\x00e\\x00s|\\x00m\\x00e\\x00e\\x00t|\\x00g\\x00l\\x00o\\x00b\\x00a\\x00l|\\x00m\\x00e\\x00n\\x00u|\\x00s\\x00t\\x00y\\x00l\\x00e|\\x00s\\x00v|\\x00b\\x00e|\\x00t\\x00h|\\x00c\\x00r\\x00e\\x00d\\x00i\\x00t\\x00c\\x00a\\x00r\\x00d|\\x00t\\x00f|\\x00t\\x00o\\x00k\\x00y\\x00o|\\x00b\\x00o|\\x00d\\x00a\\x00b\\x00u\\x00r|\\x00l\\x00i\\x00f\\x00e|\\x00y\\x00e|\\x00t\\x00z|\\x00l\\x00t\\x00d\\x00a|\\x00w\\x00a\\x00t\\x00c\\x00h|\\x00t\\x00p|\\x00m\\x00a\\x00n\\x00g\\x00o|\\x00m\\x00o\\x00n\\x00a\\x00s\\x00h|\\x00u\\x00z|\\x00l\\x00i\\x00m\\x00o|\\x00b\\x00a\\x00n\\x00k|\\x00d\\x00u\\x00r\\x00b\\x00a\\x00n|\\x00s\\x00p\\x00i\\x00e\\x00g\\x00e\\x00l|\\x00q\\x00u\\x00e\\x00b\\x00e\\x00c|\\x00c\\x00w|\\x00m\\x00u|\\x00v\\x00o\\x00t\\x00e|\\x00c\\x00a\\x00r\\x00e\\x00e\\x00r\\x00s|\\x00c\\x00a\\x00p\\x00e\\x00t\\x00o\\x00w\\x00n|\\x00a\\x00m\\x00s\\x00t\\x00e\\x00r\\x00d\\x00a\\x00m|\\x00b\\x00m\\x00w|\\x00c\\x00k|\\x00g\\x00a\\x00r\\x00d\\x00e\\x00n|\\x00m\\x00a|\\x00n\\x00o|\\x00m\\x00g|\\x00c\\x00o\\x00m\\x00m\\x00u\\x00n\\x00i\\x00t\\x00y|\\x00t\\x00r\\x00a\\x00v\\x00e\\x00l|\\x00v\\x00e\\x00n\\x00t\\x00u\\x00r\\x00e\\x00s|\\x00n\\x00i|\\x00m\\x00m|\\x00p\\x00r|\\x00d\\x00m|\\x00n\\x00c|\\x00a\\x00d\\x00u\\x00l\\x00t|\\x00p\\x00h|\\x00d\\x00k|\\x00p\\x00n|\\x00p\\x00r\\x00o\\x00p\\x00e\\x00r\\x00t\\x00i\\x00e\\x00s|\\x00f\\x00a\\x00s\\x00h\\x00i\\x00o\\x00n|\\x00s\\x00e\\x00x\\x00y|\\x00h\\x00u|\\x00c\\x00a\\x00m\\x00p|\\x00o\\x00n\\x00g|\\x00r\\x00e\\x00p\\x00u\\x00b\\x00l\\x00i\\x00c\\x00a\\x00n|\\x00d\\x00e\\x00m\\x00o\\x00c\\x00r\\x00a\\x00t|\\x00k\\x00i\\x00t\\x00c\\x00h\\x00e\\x00n|\\x00e\\x00c|\\x00f\\x00l\\x00y|\\x00b\\x00e\\x00s\\x00t|\\x00m\\x00o\\x00d\\x00a|\\x00p\\x00r\\x00o\\x00d|\\x00n\\x00e\\x00w|\\x00a\\x00b\\x00o\\x00g\\x00a\\x00d\\x00o|\\x00t\\x00o\\x00s\\x00h\\x00i\\x00b\\x00a|\\x00c\\x00r\\x00e\\x00d\\x00i\\x00t|\\x00o\\x00k\\x00i\\x00n\\x00a\\x00w\\x00a|\\x00s\\x00c\\x00h\\x00m\\x00i\\x00d\\x00t|\\x00s\\x00c\\x00h\\x00w\\x00a\\x00r\\x00z|\\x00s\\x00c\\x00i\\x00e\\x00n\\x00c\\x00e|\\x00i\\x00n\\x00s\\x00u\\x00r\\x00e|\\x00s\\x00c\\x00o\\x00t|\\x00d\\x00a\\x00n\\x00c\\x00e|\\x00f\\x00u\\x00t\\x00b\\x00o\\x00l|\\x00i\\x00m|\\x00i\\x00n\\x00d\\x00u\\x00s\\x00t\\x00r\\x00i\\x00e\\x00s|\\x00t\\x00e\\x00l|\\x00g\\x00u\\x00i\\x00t\\x00a\\x00r\\x00s|\\x00t\\x00r\\x00a\\x00d\\x00e|\\x00l\\x00a\\x00n\\x00d|\\x00c\\x00a\\x00p\\x00i\\x00t\\x00a\\x00l|\\x00t\\x00o\\x00w\\x00n|\\x00t\\x00i\\x00r\\x00e\\x00s|\\x00k\\x00y\\x00o\\x00t\\x00o|\\x00c\\x00y\\x00m\\x00r\\x00u|\\x00c\\x00u\\x00i\\x00s\\x00i\\x00n\\x00e\\x00l\\x00l\\x00a|\\x00s\\x00p\\x00a\\x00c\\x00e|\\x00l\\x00a\\x00c\\x00a\\x00i\\x00x\\x00a|\\x00w\\x00e\\x00d|\\x00g\\x00m\\x00o|\\x00g\\x00o\\x00o\\x00g\\x00l\\x00e|\\x00e\\x00x\\x00p\\x00o\\x00s\\x00e\\x00d|\\x00k\\x00i\\x00m|\\x00w\\x00e\\x00b\\x00s\\x00i\\x00t\\x00e|\\x00g\\x00p|\\x00j\\x00e|\\x00s\\x00m|\\x00w\\x00o\\x00r\\x00k|\\x00k\\x00g|\\x00m\\x00e\\x00l\\x00b\\x00o\\x00u\\x00r\\x00n\\x00e|\\x00n\\x00g\\x00o|\\x00l\\x00u|\\x00s\\x00g|\\x00f\\x00l\\x00o\\x00w\\x00e\\x00r\\x00s|\\x00a\\x00n|\\x00t\\x00r\\x00a\\x00i\\x00n\\x00i\\x00n\\x00g|\\x00l\\x00s|\\x00b\\x00u\\x00i\\x00l\\x00d\\x00e\\x00r\\x00s|\\x00g\\x00f|\\x00s\\x00a|\\x00a\\x00t|\\x00l\\x00y|\\x00s\\x00h\\x00i\\x00k\\x00s\\x00h\\x00a|\\x00g\\x00h|\\x00c\\x00o\\x00n\\x00s\\x00t\\x00r\\x00u\\x00c\\x00t\\x00i\\x00o\\x00n|\\x00a\\x00r|\\x00c\\x00a\\x00l|\\x00p\\x00a\\x00r\\x00t\\x00y|\\x00b\\x00j|\\x00s\\x00u|\\x00g\\x00l\\x00e|\\x00a\\x00x|\\x00t\\x00g|\\x00b\\x00i\\x00k\\x00e|\\x00c\\x00o\\x00u\\x00n\\x00t\\x00r\\x00y|\\x00d\\x00a\\x00y|\\x00m\\x00o\\x00n\\x00e\\x00y|\\x00b\\x00i\\x00o|\\x00l\\x00k|\\x00b\\x00v|\\x00d\\x00e\\x00l\\x00i\\x00v\\x00e\\x00r\\x00y|\\x00u\\x00k|\\x00g\\x00o\\x00o\\x00g|\\x00c\\x00h\\x00u\\x00r\\x00c\\x00h|\\x00c\\x00i\\x00t\\x00y|\\x00e\\x00x\\x00p\\x00e\\x00r\\x00t|\\x00b\\x00i\\x00z|\\x00u\\x00a|\\x00r\\x00e\\x00i\\x00s\\x00e|\\x00u\\x00g|\\x00e\\x00u\\x00r\\x00o\\x00v\\x00i\\x00s\\x00i\\x00o\\x00n|\\x00l\\x00o\\x00t\\x00t\\x00e|\\x00v\\x00e\\x00g\\x00a\\x00s|\\x00p\\x00r\\x00e\\x00s\\x00s|\\x00v\\x00c|\\x00u\\x00s|\\x00f\\x00l\\x00s\\x00m\\x00i\\x00d\\x00t\\x00h|\\x00c\\x00o\\x00n\\x00t\\x00r\\x00a\\x00c\\x00t\\x00o\\x00r\\x00s|\\x00e\\x00m\\x00a\\x00i\\x00l|\\x00s\\x00a\\x00r\\x00l|\\x00c\\x00v|\\x00f\\x00r\\x00l|\\x00j\\x00u\\x00e\\x00g\\x00o\\x00s|\\x00s\\x00e\\x00w|\\x00m\\x00t|\\x00e\\x00n\\x00g\\x00i\\x00n\\x00e\\x00e\\x00r\\x00i\\x00n\\x00g|\\x00w\\x00i\\x00e\\x00n|\\x00m\\x00z|\\x00s\\x00e\\x00r\\x00v\\x00i\\x00c\\x00e\\x00s|\\x00o\\x00n\\x00l|\\x00d\\x00z|\\x00y\\x00a\\x00n\\x00d\\x00e\\x00x|\\x00c\\x00d|\\x00m\\x00i\\x00n\\x00i|\\x00b\\x00a\\x00n\\x00d|\\x00n\\x00l|\\x00h\\x00a\\x00n\\x00g\\x00o\\x00u\\x00t|\\x00n\\x00f|\\x00m\\x00l|\\x00p\\x00s|\\x00p\\x00o\\x00s\\x00t|\\x00z\\x00m|\\x00s\\x00u\\x00r\\x00f|\\x00y\\x00o\\x00k\\x00o\\x00h\\x00a\\x00m\\x00a|\\x00n\\x00z|\\x00g\\x00r\\x00a\\x00t\\x00i\\x00s|\\x00c\\x00a\\x00n\\x00c\\x00e\\x00r\\x00r\\x00e\\x00s\\x00e\\x00a\\x00r\\x00c\\x00h|\\x00r\\x00o\\x00d\\x00e\\x00o|\\x00p\\x00e|\\x00c\\x00e\\x00o|\\x00q\\x00a|\\x00w\\x00i\\x00l\\x00l\\x00i\\x00a\\x00m\\x00h\\x00i\\x00l\\x00l|\\x00r\\x00w|\\x00m\\x00a\\x00r\\x00k\\x00e\\x00t\\x00i\\x00n\\x00g|\\x00o\\x00t\\x00s\\x00u\\x00k\\x00a|\\x00p\\x00a\\x00r\\x00t\\x00n\\x00e\\x00r\\x00s|\\x00d\\x00e\\x00g\\x00r\\x00e\\x00e|\\x00l\\x00a\\x00w\\x00y\\x00e\\x00r|\\x00x\\x00y\\x00z|\\x00d\\x00e\\x00n\\x00t\\x00i\\x00s\\x00t|\\x00s\\x00k\\x00y|\\x00c\\x00o\\x00n\\x00s\\x00u\\x00l\\x00t\\x00i\\x00n\\x00g|\\x00a\\x00u\\x00t\\x00o\\x00s|\\x00r\\x00e|\\x00a\\x00i\\x00r\\x00f\\x00o\\x00r\\x00c\\x00e|\\x00d\\x00a\\x00d|\\x00p\\x00l\\x00a\\x00c\\x00e|\\x00p\\x00h\\x00o\\x00t\\x00o|\\x00b\\x00a\\x00r\\x00c\\x00l\\x00a\\x00y\\x00s|\\x00r\\x00o|\\x00c\\x00r\\x00i\\x00c\\x00k\\x00e\\x00t|\\x00i\\x00l|\\x00v\\x00e\\x00r\\x00s\\x00i\\x00c\\x00h\\x00e\\x00r\\x00u\\x00n\\x00g|\\x00s\\x00o\\x00h\\x00u|\\x00a\\x00q\\x00u\\x00a\\x00r\\x00e\\x00l\\x00l\\x00e|\\x00c\\x00a\\x00m\\x00e\\x00r\\x00a|\\x00f\\x00a\\x00i\\x00l|\\x00a\\x00u\\x00d\\x00i\\x00o|\\x00s\\x00u\\x00p\\x00p\\x00o\\x00r\\x00t|\\x00b\\x00l\\x00u\\x00e|\\x00k\\x00r|\\x00a\\x00c\\x00c\\x00o\\x00u\\x00n\\x00t\\x00a\\x00n\\x00t\\x00s|\\x00b\\x00e\\x00e\\x00r|\\x00m\\x00o\\x00s\\x00c\\x00o\\x00w|\\x00g\\x00w|\\x00e\\x00n\\x00e\\x00r\\x00g\\x00y|\\x00f\\x00o|\\x00a\\x00e|\\x00s\\x00u\\x00p\\x00p\\x00l\\x00y|\\x00g\\x00a\\x00l|\\x00s\\x00l|\\x00g\\x00y|\\x00f\\x00i|\\x00a\\x00c|\\x00r\\x00e\\x00c\\x00i\\x00p\\x00e\\x00s|\\x00l\\x00i\\x00n\\x00k|\\x00h\\x00o\\x00l\\x00i\\x00d\\x00a\\x00y|\\x00l\\x00v|\\x00b\\x00l\\x00a\\x00c\\x00k|\\x00a\\x00i|\\x00h\\x00a\\x00m\\x00b\\x00u\\x00r\\x00g|\\x00a\\x00e\\x00r\\x00o|\\x00f\\x00i\\x00n\\x00a\\x00n\\x00c\\x00i\\x00a\\x00l|\\x00g\\x00e|\\x00a\\x00u\\x00c\\x00t\\x00i\\x00o\\x00n|\\x00s\\x00o\\x00l\\x00a\\x00r|\\x00a\\x00w|\\x00p\\x00i\\x00n\\x00k|\\x00t\\x00l|\\x00s\\x00z|\\x00s\\x00a\\x00m\\x00s\\x00u\\x00n\\x00g|\\x00b\\x00a|\\x00k\\x00r\\x00d|\\x00t\\x00j|\\x00s\\x00t|\\x00z\\x00u\\x00e\\x00r\\x00i\\x00c\\x00h|\\x00t\\x00o\\x00y\\x00s|\\x00b\\x00m|\\x00c\\x00a\\x00r\\x00a\\x00v\\x00a\\x00n|\\x00f\\x00u\\x00r\\x00n\\x00i\\x00t\\x00u\\x00r\\x00e|\\x00r\\x00y\\x00u\\x00k\\x00y\\x00u|\\x00b\\x00w|\\x00m\\x00a\\x00r\\x00k\\x00e\\x00t|\\x00t\\x00t|\\x00b\\x00y|\\x00m\\x00u\\x00s\\x00e\\x00u\\x00m|\\x00t\\x00r|\\x00w\\x00h\\x00o\\x00s\\x00w\\x00h\\x00o|\\x00p\\x00r\\x00a\\x00x\\x00i|\\x00c\\x00a\\x00r\\x00t\\x00i\\x00e\\x00r|\\x00k\\x00o\\x00e\\x00l\\x00n|\\x00w\\x00o\\x00r\\x00k\\x00s|\\x00b\\x00i\\x00d|\\x00d\\x00e\\x00s\\x00i\\x00g\\x00n|\\x00i\\x00b\\x00m|\\x00p\\x00r\\x00o\\x00p\\x00e\\x00r\\x00t\\x00y|\\x00l\\x00a\\x00t|\\x00e\\x00v\\x00e\\x00r\\x00b\\x00a\\x00n\\x00k|\\x00v\\x00a\\x00c\\x00a\\x00t\\x00i\\x00o\\x00n\\x00s|\\x00m\\x00q|\\x00u\\x00n\\x00o|\\x00v\\x00i\\x00l\\x00l\\x00a\\x00s|\\x00c\\x00h\\x00r\\x00o\\x00m\\x00e|\\x00c\\x00u|\\x00t\\x00i\\x00r\\x00o\\x00l|\\x00m\\x00w|\\x00c\\x00o|\\x00r\\x00e\\x00n|\\x00r\\x00e\\x00v\\x00i\\x00e\\x00w\\x00s|\\x00c\\x00i|\\x00a\\x00c\\x00t\\x00o\\x00r|\\x00n\\x00e\\x00t|\\x00m\\x00a\\x00r\\x00r\\x00i\\x00o\\x00t\\x00t|\\x00m\\x00c|\\x00t\\x00a\\x00t\\x00a\\x00r|\\x00c\\x00c|\\x00n\\x00g|\\x00m\\x00o|\\x00v\\x00e\\x00t|\\x00p\\x00t|\\x00d\\x00o|\\x00n\\x00a|\\x00b\\x00r\\x00u\\x00s\\x00s\\x00e\\x00l\\x00s|\\x00h\\x00k|\\x00d\\x00e|\\x00e\\x00s|\\x00c\\x00a\\x00s\\x00a|\\x00o\\x00m|\\x00e\\x00u\\x00s|\\x00f\\x00r\\x00o\\x00g\\x00a\\x00n\\x00s|\\x00n\\x00r\\x00a|\\x00n\\x00u|\\x00p\\x00f|\\x00g\\x00r\\x00a\\x00p\\x00h\\x00i\\x00c\\x00s|\\x00p\\x00r\\x00o\\x00d\\x00u\\x00c\\x00t\\x00i\\x00o\\x00n\\x00s|\\x00g\\x00o\\x00v|\\x00e\\x00a\\x00t|\\x00e\\x00e|\\x00c\\x00o\\x00n\\x00d\\x00o\\x00s|\\x00c\\x00l\\x00a\\x00i\\x00m\\x00s|\\x00i\\x00m\\x00m\\x00o\\x00b\\x00i\\x00l\\x00i\\x00e\\x00n|\\x00w\\x00s|\\x00c\\x00o\\x00d\\x00e\\x00s|\\x00t\\x00o\\x00d\\x00a\\x00y|\\x00w\\x00o\\x00r\\x00l\\x00d|\\x00n\\x00a\\x00m\\x00e|\\x00p\\x00h\\x00a\\x00r\\x00m\\x00a\\x00c\\x00y|\\x00h\\x00i\\x00p\\x00h\\x00o\\x00p|\\x00a\\x00n\\x00d\\x00r\\x00o\\x00i\\x00d|\\x00a\\x00r\\x00c\\x00h\\x00i|\\x00r\\x00s\\x00v\\x00p|\\x00g\\x00u\\x00r\\x00u|\\x00c\\x00l\\x00o\\x00t\\x00h\\x00i\\x00n\\x00g|\\x00b\\x00a\\x00r|\\x00i\\x00q|\\x00m\\x00o\\x00v|\\x00p\\x00h\\x00o\\x00t\\x00o\\x00s|\\x00i\\x00o|\\x00s\\x00a\\x00a\\x00r\\x00l\\x00a\\x00n\\x00d|\\x00i\\x00e|\\x00t\\x00a\\x00x|\\x00c\\x00a\\x00t|\\x00c\\x00e\\x00r\\x00n|\\x00d\\x00v\\x00a\\x00g|\\x00k\\x00w|\\x00j\\x00o|\\x00h\\x00a\\x00u\\x00s|\\x00w\\x00m\\x00e|\\x00t\\x00e\\x00n\\x00n\\x00i\\x00s|\\x00a\\x00d|\\x00s\\x00k|\\x00c\\x00r\\x00s|\\x00s\\x00o\\x00c\\x00i\\x00a\\x00l|\\x00h\\x00o\\x00w)))(?:\\x00\\W|$|\\x00[\\x22\\x27])",
            "(?:^|[\\x22\\x27]\\x00|\\W\\x00)((?:((?:[\\x2d0-9a-z]\\x00){4,}(?:\\x5b\\x00)?\\x2e\\x00(?:\\x5d\\x00)?))+((?:i\\x00m\\x00m\\x00o\\x00|h\\x00i\\x00v\\x00|h\\x00o\\x00m\\x00e\\x00s\\x00|i\\x00n\\x00k\\x00|b\\x00a\\x00n\\x00d\\x00|b\\x00s\\x00|g\\x00l\\x00o\\x00b\\x00o\\x00|k\\x00e\\x00|s\\x00c\\x00i\\x00e\\x00n\\x00c\\x00e\\x00|f\\x00i\\x00t\\x00|c\\x00y\\x00|s\\x00z\\x00|d\\x00e\\x00l\\x00i\\x00v\\x00e\\x00r\\x00y\\x00|b\\x00i\\x00o\\x00|g\\x00b\\x00|h\\x00m\\x00|z\\x00u\\x00e\\x00r\\x00i\\x00c\\x00h\\x00|w\\x00m\\x00e\\x00|t\\x00i\\x00r\\x00e\\x00s\\x00|k\\x00m\\x00|l\\x00a\\x00t\\x00r\\x00o\\x00b\\x00e\\x00|s\\x00e\\x00w\\x00|s\\x00c\\x00h\\x00u\\x00l\\x00e\\x00|m\\x00i\\x00a\\x00m\\x00i\\x00|g\\x00m\\x00x\\x00|s\\x00r\\x00|u\\x00y\\x00|v\\x00c\\x00|i\\x00s\\x00|r\\x00u\\x00h\\x00r\\x00|a\\x00n\\x00d\\x00r\\x00o\\x00i\\x00d\\x00|u\\x00o\\x00l\\x00|s\\x00j\\x00|d\\x00e\\x00n\\x00t\\x00i\\x00s\\x00t\\x00|k\\x00i\\x00w\\x00i\\x00|m\\x00h\\x00|e\\x00t\\x00|g\\x00r\\x00|s\\x00t\\x00y\\x00l\\x00e\\x00|l\\x00i\\x00f\\x00e\\x00|m\\x00o\\x00n\\x00a\\x00s\\x00h\\x00|a\\x00r\\x00|s\\x00b\\x00|u\\x00n\\x00o\\x00|m\\x00p\\x00|c\\x00r\\x00s\\x00|m\\x00o\\x00v\\x00|w\\x00i\\x00l\\x00l\\x00i\\x00a\\x00m\\x00h\\x00i\\x00l\\x00l\\x00|g\\x00o\\x00p\\x00|p\\x00a\\x00|j\\x00o\\x00b\\x00u\\x00r\\x00g\\x00|h\\x00u\\x00|y\\x00a\\x00n\\x00d\\x00e\\x00x\\x00|a\\x00z\\x00|a\\x00s\\x00i\\x00a\\x00|c\\x00l\\x00|n\\x00h\\x00k\\x00|d\\x00i\\x00r\\x00e\\x00c\\x00t\\x00o\\x00r\\x00y\\x00|t\\x00o\\x00o\\x00l\\x00s\\x00|m\\x00x\\x00|s\\x00u\\x00z\\x00u\\x00k\\x00i\\x00|i\\x00n\\x00v\\x00e\\x00s\\x00t\\x00m\\x00e\\x00n\\x00t\\x00s\\x00|u\\x00a\\x00|f\\x00a\\x00s\\x00h\\x00i\\x00o\\x00n\\x00|b\\x00l\\x00o\\x00o\\x00m\\x00b\\x00e\\x00r\\x00g\\x00|h\\x00e\\x00r\\x00m\\x00e\\x00s\\x00|a\\x00i\\x00r\\x00f\\x00o\\x00r\\x00c\\x00e\\x00|w\\x00e\\x00b\\x00c\\x00a\\x00m\\x00|d\\x00o\\x00m\\x00a\\x00i\\x00n\\x00s\\x00|r\\x00i\\x00c\\x00h\\x00|i\\x00n\\x00|c\\x00l\\x00a\\x00i\\x00m\\x00s\\x00|c\\x00d\\x00|g\\x00o\\x00o\\x00g\\x00|e\\x00u\\x00s\\x00|t\\x00w\\x00|n\\x00i\\x00|w\\x00a\\x00n\\x00g\\x00|o\\x00r\\x00g\\x00|c\\x00l\\x00u\\x00b\\x00|o\\x00t\\x00s\\x00u\\x00k\\x00a\\x00|k\\x00d\\x00d\\x00i\\x00|b\\x00l\\x00u\\x00e\\x00|c\\x00a\\x00m\\x00p\\x00|g\\x00a\\x00l\\x00|p\\x00l\\x00u\\x00m\\x00b\\x00i\\x00n\\x00g\\x00|t\\x00o\\x00|c\\x00l\\x00o\\x00t\\x00h\\x00i\\x00n\\x00g\\x00|n\\x00a\\x00|l\\x00a\\x00n\\x00d\\x00|c\\x00a\\x00r\\x00a\\x00v\\x00a\\x00n\\x00|e\\x00v\\x00e\\x00n\\x00t\\x00s\\x00|v\\x00e\\x00g\\x00a\\x00s\\x00|f\\x00a\\x00r\\x00m\\x00|b\\x00t\\x00|t\\x00i\\x00e\\x00n\\x00d\\x00a\\x00|l\\x00o\\x00t\\x00t\\x00o\\x00|s\\x00y\\x00|z\\x00m\\x00|m\\x00a\\x00n\\x00g\\x00o\\x00|t\\x00u\\x00i\\x00|c\\x00l\\x00i\\x00n\\x00i\\x00c\\x00|e\\x00g\\x00|t\\x00g\\x00|g\\x00a\\x00|n\\x00g\\x00o\\x00|e\\x00a\\x00t\\x00|h\\x00e\\x00r\\x00e\\x00|w\\x00a\\x00l\\x00e\\x00s\\x00|o\\x00v\\x00h\\x00|c\\x00i\\x00t\\x00i\\x00c\\x00|j\\x00c\\x00b\\x00|w\\x00e\\x00d\\x00|k\\x00h\\x00|p\\x00o\\x00s\\x00t\\x00|m\\x00c\\x00|g\\x00i\\x00|v\\x00a\\x00c\\x00a\\x00t\\x00i\\x00o\\x00n\\x00s\\x00|c\\x00a\\x00t\\x00|u\\x00n\\x00i\\x00v\\x00e\\x00r\\x00s\\x00i\\x00t\\x00y\\x00|a\\x00u\\x00|c\\x00r\\x00i\\x00c\\x00k\\x00e\\x00t\\x00|b\\x00d\\x00|l\\x00i\\x00d\\x00l\\x00|k\\x00p\\x00|l\\x00e\\x00a\\x00s\\x00e\\x00|c\\x00a\\x00r\\x00d\\x00s\\x00|s\\x00i\\x00|n\\x00a\\x00g\\x00o\\x00y\\x00a\\x00|w\\x00a\\x00t\\x00c\\x00h\\x00|m\\x00k\\x00|w\\x00i\\x00k\\x00i\\x00|g\\x00u\\x00r\\x00u\\x00|p\\x00a\\x00r\\x00i\\x00s\\x00|g\\x00q\\x00|e\\x00u\\x00r\\x00o\\x00v\\x00i\\x00s\\x00i\\x00o\\x00n\\x00|s\\x00a\\x00l\\x00e\\x00|d\\x00n\\x00p\\x00|p\\x00f\\x00|d\\x00a\\x00b\\x00u\\x00r\\x00|q\\x00u\\x00e\\x00b\\x00e\\x00c\\x00|s\\x00h\\x00o\\x00e\\x00s\\x00|b\\x00o\\x00u\\x00t\\x00i\\x00q\\x00u\\x00e\\x00|e\\x00s\\x00q\\x00|v\\x00e\\x00r\\x00s\\x00i\\x00c\\x00h\\x00e\\x00r\\x00u\\x00n\\x00g\\x00|v\\x00e\\x00t\\x00|l\\x00e\\x00g\\x00a\\x00l\\x00|v\\x00o\\x00y\\x00a\\x00g\\x00e\\x00|c\\x00l\\x00e\\x00a\\x00n\\x00i\\x00n\\x00g\\x00|s\\x00a\\x00|f\\x00i\\x00s\\x00h\\x00i\\x00n\\x00g\\x00|m\\x00s\\x00|a\\x00d\\x00u\\x00l\\x00t\\x00|l\\x00i\\x00n\\x00k\\x00|n\\x00z\\x00|g\\x00y\\x00|c\\x00a\\x00r\\x00e\\x00e\\x00r\\x00|p\\x00n\\x00|e\\x00d\\x00u\\x00|h\\x00r\\x00|a\\x00e\\x00|c\\x00k\\x00|a\\x00x\\x00a\\x00|c\\x00a\\x00l\\x00|c\\x00o\\x00m\\x00p\\x00u\\x00t\\x00e\\x00r\\x00|l\\x00o\\x00t\\x00t\\x00e\\x00|t\\x00o\\x00p\\x00|v\\x00o\\x00d\\x00k\\x00a\\x00|b\\x00a\\x00n\\x00k\\x00|f\\x00k\\x00|n\\x00r\\x00|b\\x00u\\x00s\\x00i\\x00n\\x00e\\x00s\\x00s\\x00|a\\x00m\\x00|r\\x00e\\x00i\\x00t\\x00|a\\x00c\\x00t\\x00o\\x00r\\x00|c\\x00c\\x00|r\\x00y\\x00u\\x00k\\x00y\\x00u\\x00|g\\x00a\\x00l\\x00l\\x00e\\x00r\\x00y\\x00|c\\x00a\\x00t\\x00e\\x00r\\x00i\\x00n\\x00g\\x00|b\\x00a\\x00r\\x00c\\x00l\\x00a\\x00y\\x00c\\x00a\\x00r\\x00d\\x00|d\\x00c\\x00l\\x00k\\x00|t\\x00t\\x00|b\\x00i\\x00k\\x00e\\x00|t\\x00a\\x00i\\x00p\\x00e\\x00i\\x00|s\\x00e\\x00x\\x00y\\x00|r\\x00e\\x00n\\x00|k\\x00g\\x00|r\\x00o\\x00|l\\x00u\\x00|k\\x00i\\x00t\\x00c\\x00h\\x00e\\x00n\\x00|m\\x00o\\x00t\\x00o\\x00r\\x00c\\x00y\\x00c\\x00l\\x00e\\x00s\\x00|t\\x00l\\x00|g\\x00g\\x00e\\x00e\\x00|c\\x00o\\x00m\\x00m\\x00u\\x00n\\x00i\\x00t\\x00y\\x00|b\\x00y\\x00|e\\x00m\\x00e\\x00r\\x00c\\x00k\\x00|a\\x00m\\x00s\\x00t\\x00e\\x00r\\x00d\\x00a\\x00m\\x00|s\\x00o\\x00l\\x00u\\x00t\\x00i\\x00o\\x00n\\x00s\\x00|r\\x00w\\x00|s\\x00t\\x00|t\\x00d\\x00|g\\x00d\\x00|s\\x00o\\x00y\\x00|v\\x00a\\x00|b\\x00n\\x00p\\x00p\\x00a\\x00r\\x00i\\x00b\\x00a\\x00s\\x00|p\\x00r\\x00o\\x00p\\x00e\\x00r\\x00t\\x00i\\x00e\\x00s\\x00|b\\x00a\\x00|i\\x00q\\x00|k\\x00w\\x00|s\\x00l\\x00|i\\x00r\\x00i\\x00s\\x00h\\x00|e\\x00r\\x00|g\\x00l\\x00|w\\x00t\\x00f\\x00|e\\x00x\\x00c\\x00h\\x00a\\x00n\\x00g\\x00e\\x00|l\\x00a\\x00t\\x00|v\\x00i\\x00|d\\x00i\\x00e\\x00t\\x00|i\\x00f\\x00m\\x00|v\\x00l\\x00a\\x00a\\x00n\\x00d\\x00e\\x00r\\x00e\\x00n\\x00|b\\x00i\\x00|s\\x00c\\x00o\\x00t\\x00|r\\x00e\\x00a\\x00l\\x00t\\x00o\\x00r\\x00|c\\x00h\\x00a\\x00n\\x00n\\x00e\\x00l\\x00|c\\x00a\\x00p\\x00i\\x00t\\x00a\\x00l\\x00|n\\x00e\\x00x\\x00u\\x00s\\x00|t\\x00e\\x00l\\x00|g\\x00o\\x00o\\x00g\\x00l\\x00e\\x00|s\\x00d\\x00|m\\x00n\\x00|f\\x00l\\x00o\\x00w\\x00e\\x00r\\x00s\\x00|g\\x00t\\x00|b\\x00o\\x00o\\x00|o\\x00m\\x00|n\\x00e\\x00w\\x00|c\\x00l\\x00i\\x00c\\x00k\\x00|l\\x00a\\x00w\\x00y\\x00e\\x00r\\x00|a\\x00x\\x00|f\\x00i\\x00n\\x00a\\x00n\\x00c\\x00e\\x00|m\\x00o\\x00s\\x00c\\x00o\\x00w\\x00|c\\x00n\\x00|l\\x00b\\x00|m\\x00v\\x00|v\\x00i\\x00l\\x00l\\x00a\\x00s\\x00|d\\x00a\\x00y\\x00|r\\x00e\\x00i\\x00s\\x00e\\x00n\\x00|p\\x00k\\x00|w\\x00o\\x00r\\x00k\\x00s\\x00|i\\x00l\\x00|s\\x00a\\x00r\\x00l\\x00|c\\x00f\\x00|i\\x00b\\x00m\\x00|h\\x00e\\x00l\\x00p\\x00|t\\x00i\\x00p\\x00s\\x00|t\\x00a\\x00x\\x00|v\\x00i\\x00s\\x00i\\x00o\\x00n\\x00|s\\x00h\\x00r\\x00i\\x00r\\x00a\\x00m\\x00|n\\x00o\\x00|c\\x00o\\x00n\\x00s\\x00u\\x00l\\x00t\\x00i\\x00n\\x00g\\x00|r\\x00e\\x00n\\x00t\\x00a\\x00l\\x00s\\x00|s\\x00u\\x00p\\x00p\\x00o\\x00r\\x00t\\x00|u\\x00g\\x00|g\\x00i\\x00f\\x00t\\x00s\\x00|p\\x00s\\x00|v\\x00o\\x00t\\x00e\\x00|i\\x00d\\x00|w\\x00i\\x00e\\x00n\\x00|i\\x00n\\x00s\\x00u\\x00r\\x00e\\x00|n\\x00e\\x00t\\x00|t\\x00a\\x00t\\x00t\\x00o\\x00o\\x00|l\\x00r\\x00|c\\x00a\\x00p\\x00e\\x00t\\x00o\\x00w\\x00n\\x00|x\\x00y\\x00z\\x00|r\\x00o\\x00c\\x00k\\x00s\\x00|b\\x00a\\x00y\\x00e\\x00r\\x00n\\x00|h\\x00o\\x00l\\x00d\\x00i\\x00n\\x00g\\x00s\\x00|n\\x00a\\x00m\\x00e\\x00|g\\x00u\\x00i\\x00d\\x00e\\x00|i\\x00n\\x00s\\x00t\\x00i\\x00t\\x00u\\x00t\\x00e\\x00|n\\x00g\\x00|c\\x00o\\x00l\\x00o\\x00g\\x00n\\x00e\\x00|e\\x00n\\x00g\\x00i\\x00n\\x00e\\x00e\\x00r\\x00i\\x00n\\x00g\\x00|f\\x00u\\x00n\\x00d\\x00|s\\x00p\\x00a\\x00c\\x00e\\x00|b\\x00r\\x00|h\\x00a\\x00n\\x00g\\x00o\\x00u\\x00t\\x00|c\\x00a\\x00n\\x00c\\x00e\\x00r\\x00r\\x00e\\x00s\\x00e\\x00a\\x00r\\x00c\\x00h\\x00|c\\x00v\\x00|b\\x00a\\x00r\\x00c\\x00l\\x00a\\x00y\\x00s\\x00|d\\x00i\\x00r\\x00e\\x00c\\x00t\\x00|o\\x00o\\x00o\\x00|t\\x00r\\x00a\\x00v\\x00e\\x00l\\x00|e\\x00e\\x00|v\\x00i\\x00d\\x00e\\x00o\\x00|b\\x00i\\x00n\\x00g\\x00o\\x00|i\\x00n\\x00t\\x00|c\\x00o\\x00f\\x00f\\x00e\\x00e\\x00|g\\x00l\\x00e\\x00|b\\x00z\\x00|i\\x00t\\x00|b\\x00i\\x00d\\x00|d\\x00k\\x00|e\\x00s\\x00t\\x00a\\x00t\\x00e\\x00|m\\x00a\\x00|u\\x00z\\x00|a\\x00r\\x00m\\x00y\\x00|m\\x00o\\x00r\\x00t\\x00g\\x00a\\x00g\\x00e\\x00|o\\x00n\\x00g\\x00|c\\x00u\\x00i\\x00s\\x00i\\x00n\\x00e\\x00l\\x00l\\x00a\\x00|s\\x00c\\x00a\\x00|b\\x00b\\x00|b\\x00u\\x00z\\x00z\\x00|k\\x00r\\x00|p\\x00r\\x00o\\x00d\\x00|s\\x00k\\x00|p\\x00i\\x00c\\x00s\\x00|e\\x00u\\x00|g\\x00s\\x00|m\\x00e\\x00e\\x00t\\x00|g\\x00r\\x00a\\x00t\\x00i\\x00s\\x00|f\\x00i\\x00r\\x00m\\x00d\\x00a\\x00l\\x00e\\x00|f\\x00i\\x00t\\x00n\\x00e\\x00s\\x00s\\x00|b\\x00j\\x00|r\\x00e\\x00s\\x00t\\x00a\\x00u\\x00r\\x00a\\x00n\\x00t\\x00|k\\x00z\\x00|h\\x00o\\x00u\\x00s\\x00e\\x00|s\\x00c\\x00|m\\x00q\\x00|a\\x00s\\x00s\\x00o\\x00c\\x00i\\x00a\\x00t\\x00e\\x00s\\x00|b\\x00i\\x00z\\x00|c\\x00a\\x00s\\x00h\\x00|p\\x00a\\x00r\\x00t\\x00s\\x00|t\\x00e\\x00n\\x00n\\x00i\\x00s\\x00|i\\x00m\\x00m\\x00o\\x00b\\x00i\\x00l\\x00i\\x00e\\x00n\\x00|h\\x00t\\x00|p\\x00h\\x00a\\x00r\\x00m\\x00a\\x00c\\x00y\\x00|o\\x00k\\x00i\\x00n\\x00a\\x00w\\x00a\\x00|b\\x00r\\x00u\\x00s\\x00s\\x00e\\x00l\\x00s\\x00|p\\x00r\\x00o\\x00p\\x00e\\x00r\\x00t\\x00y\\x00|c\\x00m\\x00|m\\x00e\\x00l\\x00b\\x00o\\x00u\\x00r\\x00n\\x00e\\x00|p\\x00r\\x00e\\x00s\\x00s\\x00|p\\x00i\\x00c\\x00t\\x00u\\x00r\\x00e\\x00s\\x00|g\\x00l\\x00a\\x00s\\x00s\\x00|f\\x00i\\x00|m\\x00y\\x00|e\\x00q\\x00u\\x00i\\x00p\\x00m\\x00e\\x00n\\x00t\\x00|n\\x00p\\x00|c\\x00o\\x00o\\x00l\\x00|d\\x00a\\x00d\\x00|h\\x00a\\x00m\\x00b\\x00u\\x00r\\x00g\\x00|a\\x00r\\x00c\\x00h\\x00i\\x00|p\\x00h\\x00|i\\x00o\\x00|c\\x00o\\x00m\\x00p\\x00a\\x00n\\x00y\\x00|a\\x00c\\x00|e\\x00m\\x00a\\x00i\\x00l\\x00|l\\x00u\\x00x\\x00u\\x00r\\x00y\\x00|r\\x00e\\x00|t\\x00v\\x00|k\\x00i\\x00m\\x00|i\\x00n\\x00t\\x00e\\x00r\\x00n\\x00a\\x00t\\x00i\\x00o\\x00n\\x00a\\x00l\\x00|t\\x00r\\x00u\\x00s\\x00t\\x00|d\\x00e\\x00n\\x00t\\x00a\\x00l\\x00|s\\x00u\\x00r\\x00f\\x00|b\\x00m\\x00w\\x00|f\\x00i\\x00s\\x00h\\x00|o\\x00n\\x00e\\x00|m\\x00i\\x00l\\x00|t\\x00n\\x00|c\\x00h\\x00u\\x00r\\x00c\\x00h\\x00|b\\x00w\\x00|w\\x00t\\x00c\\x00|r\\x00u\\x00|c\\x00u\\x00|s\\x00v\\x00|l\\x00o\\x00n\\x00d\\x00o\\x00n\\x00|m\\x00e\\x00n\\x00u\\x00|k\\x00r\\x00e\\x00d\\x00|t\\x00f\\x00|d\\x00e\\x00m\\x00o\\x00c\\x00r\\x00a\\x00t\\x00|l\\x00t\\x00d\\x00a\\x00|g\\x00f\\x00|n\\x00a\\x00v\\x00y\\x00|m\\x00a\\x00d\\x00r\\x00i\\x00d\\x00|v\\x00g\\x00|p\\x00a\\x00r\\x00t\\x00y\\x00|k\\x00a\\x00u\\x00f\\x00e\\x00n\\x00|c\\x00r\\x00e\\x00d\\x00i\\x00t\\x00|m\\x00e\\x00m\\x00o\\x00r\\x00i\\x00a\\x00l\\x00|y\\x00t\\x00|c\\x00a\\x00s\\x00a\\x00|k\\x00i\\x00|s\\x00n\\x00|h\\x00e\\x00a\\x00l\\x00t\\x00h\\x00c\\x00a\\x00r\\x00e\\x00|m\\x00d\\x00|p\\x00h\\x00o\\x00t\\x00o\\x00|g\\x00n\\x00|s\\x00c\\x00b\\x00|h\\x00o\\x00s\\x00t\\x00i\\x00n\\x00g\\x00|r\\x00e\\x00p\\x00u\\x00b\\x00l\\x00i\\x00c\\x00a\\x00n\\x00|b\\x00g\\x00|p\\x00i\\x00n\\x00k\\x00|p\\x00r\\x00o\\x00f\\x00|a\\x00b\\x00o\\x00g\\x00a\\x00d\\x00o\\x00|n\\x00r\\x00a\\x00|m\\x00l\\x00|r\\x00s\\x00v\\x00p\\x00|w\\x00s\\x00|p\\x00e\\x00|a\\x00e\\x00r\\x00o\\x00|c\\x00h\\x00a\\x00t\\x00|f\\x00o\\x00u\\x00n\\x00d\\x00a\\x00t\\x00i\\x00o\\x00n\\x00|b\\x00o\\x00|g\\x00i\\x00v\\x00e\\x00s\\x00|k\\x00y\\x00|s\\x00a\\x00m\\x00s\\x00u\\x00n\\x00g\\x00|c\\x00o\\x00n\\x00s\\x00t\\x00r\\x00u\\x00c\\x00t\\x00i\\x00o\\x00n\\x00|m\\x00a\\x00r\\x00k\\x00e\\x00t\\x00i\\x00n\\x00g\\x00|m\\x00t\\x00|n\\x00u\\x00|y\\x00o\\x00g\\x00a\\x00|y\\x00o\\x00u\\x00t\\x00u\\x00b\\x00e\\x00|p\\x00m\\x00|a\\x00u\\x00d\\x00i\\x00o\\x00|p\\x00h\\x00y\\x00s\\x00i\\x00o\\x00|a\\x00f\\x00|c\\x00h\\x00|b\\x00e\\x00s\\x00t\\x00|g\\x00m\\x00a\\x00i\\x00l\\x00|g\\x00e\\x00n\\x00t\\x00|f\\x00j\\x00|e\\x00n\\x00e\\x00r\\x00g\\x00y\\x00|a\\x00r\\x00p\\x00a\\x00|n\\x00r\\x00w\\x00|i\\x00n\\x00f\\x00o\\x00|c\\x00r\\x00u\\x00i\\x00s\\x00e\\x00s\\x00|d\\x00e\\x00g\\x00r\\x00e\\x00e\\x00|a\\x00n\\x00|f\\x00u\\x00t\\x00b\\x00o\\x00l\\x00|t\\x00k\\x00|k\\x00o\\x00e\\x00l\\x00n\\x00|f\\x00r\\x00|t\\x00i\\x00r\\x00o\\x00l\\x00|n\\x00e\\x00|m\\x00a\\x00r\\x00k\\x00e\\x00t\\x00|c\\x00o\\x00n\\x00d\\x00o\\x00s\\x00|j\\x00u\\x00e\\x00g\\x00o\\x00s\\x00|w\\x00h\\x00o\\x00s\\x00w\\x00h\\x00o\\x00|t\\x00o\\x00s\\x00h\\x00i\\x00b\\x00a\\x00|c\\x00x\\x00|s\\x00y\\x00s\\x00t\\x00e\\x00m\\x00s\\x00|c\\x00a\\x00m\\x00e\\x00r\\x00a\\x00|l\\x00t\\x00|l\\x00o\\x00a\\x00n\\x00s\\x00|e\\x00c\\x00|t\\x00c\\x00|t\\x00a\\x00t\\x00a\\x00r\\x00|r\\x00o\\x00d\\x00e\\x00o\\x00|h\\x00n\\x00|p\\x00r\\x00o\\x00|b\\x00l\\x00a\\x00c\\x00k\\x00f\\x00r\\x00i\\x00d\\x00a\\x00y\\x00|b\\x00u\\x00i\\x00l\\x00d\\x00|c\\x00h\\x00r\\x00i\\x00s\\x00t\\x00m\\x00a\\x00s\\x00|c\\x00i\\x00t\\x00y\\x00|f\\x00u\\x00r\\x00n\\x00i\\x00t\\x00u\\x00r\\x00e\\x00|c\\x00e\\x00o\\x00|s\\x00c\\x00h\\x00w\\x00a\\x00r\\x00z\\x00|t\\x00o\\x00d\\x00a\\x00y\\x00|s\\x00u\\x00|z\\x00a\\x00|c\\x00o\\x00d\\x00e\\x00s\\x00|g\\x00e\\x00|s\\x00u\\x00p\\x00p\\x00l\\x00i\\x00e\\x00s\\x00|a\\x00t\\x00t\\x00o\\x00r\\x00n\\x00e\\x00y\\x00|c\\x00a\\x00r\\x00e\\x00e\\x00r\\x00s\\x00|a\\x00u\\x00c\\x00t\\x00i\\x00o\\x00n\\x00|g\\x00b\\x00i\\x00z\\x00|i\\x00r\\x00|y\\x00o\\x00k\\x00o\\x00h\\x00a\\x00m\\x00a\\x00|d\\x00m\\x00|s\\x00m\\x00|d\\x00e\\x00s\\x00i\\x00g\\x00n\\x00|m\\x00g\\x00|e\\x00s\\x00|l\\x00d\\x00s\\x00|s\\x00k\\x00y\\x00|g\\x00m\\x00|f\\x00r\\x00o\\x00g\\x00a\\x00n\\x00s\\x00|r\\x00i\\x00o\\x00|i\\x00n\\x00d\\x00u\\x00s\\x00t\\x00r\\x00i\\x00e\\x00s\\x00|r\\x00e\\x00s\\x00t\\x00|m\\x00e\\x00m\\x00e\\x00|a\\x00q\\x00|f\\x00l\\x00i\\x00g\\x00h\\x00t\\x00s\\x00|b\\x00h\\x00|j\\x00o\\x00|c\\x00o\\x00n\\x00t\\x00r\\x00a\\x00c\\x00t\\x00o\\x00r\\x00s\\x00|m\\x00a\\x00n\\x00a\\x00g\\x00e\\x00m\\x00e\\x00n\\x00t\\x00|n\\x00e\\x00u\\x00s\\x00t\\x00a\\x00r\\x00|p\\x00o\\x00h\\x00l\\x00|d\\x00e\\x00|s\\x00e\\x00|c\\x00o\\x00m\\x00|c\\x00o\\x00o\\x00p\\x00|d\\x00e\\x00v\\x00|m\\x00o\\x00|g\\x00u\\x00|d\\x00i\\x00g\\x00i\\x00t\\x00a\\x00l\\x00|t\\x00r\\x00a\\x00d\\x00e\\x00|c\\x00o\\x00|b\\x00a\\x00r\\x00g\\x00a\\x00i\\x00n\\x00s\\x00|a\\x00q\\x00u\\x00a\\x00r\\x00e\\x00l\\x00l\\x00e\\x00|l\\x00a\\x00|l\\x00a\\x00c\\x00a\\x00i\\x00x\\x00a\\x00|r\\x00e\\x00p\\x00o\\x00r\\x00t\\x00|f\\x00o\\x00|m\\x00w\\x00|v\\x00o\\x00t\\x00o\\x00|s\\x00o\\x00c\\x00i\\x00a\\x00l\\x00|h\\x00o\\x00l\\x00i\\x00d\\x00a\\x00y\\x00|j\\x00o\\x00b\\x00s\\x00|i\\x00m\\x00|l\\x00i\\x00m\\x00i\\x00t\\x00e\\x00d\\x00|n\\x00i\\x00n\\x00j\\x00a\\x00|j\\x00e\\x00t\\x00z\\x00t\\x00|c\\x00g\\x00|d\\x00e\\x00s\\x00i\\x00|l\\x00i\\x00|m\\x00i\\x00n\\x00i\\x00|p\\x00o\\x00k\\x00e\\x00r\\x00|g\\x00u\\x00i\\x00t\\x00a\\x00r\\x00s\\x00|t\\x00p\\x00|t\\x00o\\x00w\\x00n\\x00|v\\x00u\\x00|e\\x00d\\x00u\\x00c\\x00a\\x00t\\x00i\\x00o\\x00n\\x00|s\\x00y\\x00d\\x00n\\x00e\\x00y\\x00|w\\x00f\\x00|h\\x00o\\x00w\\x00|p\\x00r\\x00|a\\x00l\\x00l\\x00f\\x00i\\x00n\\x00a\\x00n\\x00z\\x00|i\\x00e\\x00|c\\x00e\\x00r\\x00n\\x00|a\\x00i\\x00|l\\x00i\\x00m\\x00o\\x00|t\\x00h\\x00|n\\x00f\\x00|s\\x00c\\x00h\\x00m\\x00i\\x00d\\x00t\\x00|e\\x00x\\x00p\\x00o\\x00s\\x00e\\x00d\\x00|o\\x00s\\x00a\\x00k\\x00a\\x00|g\\x00l\\x00o\\x00b\\x00a\\x00l\\x00|r\\x00s\\x00|c\\x00w\\x00|s\\x00x\\x00|l\\x00y\\x00|f\\x00o\\x00r\\x00s\\x00a\\x00l\\x00e\\x00|g\\x00m\\x00o\\x00|v\\x00e\\x00|v\\x00i\\x00a\\x00j\\x00e\\x00s\\x00|h\\x00k\\x00|b\\x00e\\x00e\\x00r\\x00|p\\x00a\\x00r\\x00t\\x00n\\x00e\\x00r\\x00s\\x00|q\\x00a\\x00|s\\x00i\\x00n\\x00g\\x00l\\x00e\\x00s\\x00|d\\x00a\\x00t\\x00i\\x00n\\x00g\\x00|s\\x00p\\x00i\\x00e\\x00g\\x00e\\x00l\\x00|d\\x00j\\x00|t\\x00e\\x00m\\x00a\\x00s\\x00e\\x00k\\x00|d\\x00a\\x00n\\x00c\\x00e\\x00|g\\x00h\\x00|f\\x00i\\x00n\\x00a\\x00n\\x00c\\x00i\\x00a\\x00l\\x00|a\\x00t\\x00|m\\x00o\\x00d\\x00a\\x00|d\\x00o\\x00o\\x00s\\x00a\\x00n\\x00|b\\x00e\\x00|p\\x00i\\x00z\\x00z\\x00a\\x00|p\\x00u\\x00b\\x00|a\\x00g\\x00e\\x00n\\x00c\\x00y\\x00|o\\x00n\\x00l\\x00|s\\x00h\\x00|e\\x00v\\x00e\\x00r\\x00b\\x00a\\x00n\\x00k\\x00|h\\x00a\\x00u\\x00s\\x00|u\\x00s\\x00|g\\x00p\\x00|m\\x00o\\x00e\\x00|p\\x00g\\x00|w\\x00o\\x00r\\x00l\\x00d\\x00|m\\x00e\\x00d\\x00i\\x00a\\x00|b\\x00m\\x00|m\\x00u\\x00s\\x00e\\x00u\\x00m\\x00|d\\x00z\\x00|b\\x00l\\x00a\\x00c\\x00k\\x00|c\\x00o\\x00u\\x00n\\x00t\\x00r\\x00y\\x00|m\\x00r\\x00|u\\x00k\\x00|r\\x00e\\x00p\\x00a\\x00i\\x00r\\x00|i\\x00n\\x00g\\x00|r\\x00e\\x00c\\x00i\\x00p\\x00e\\x00s\\x00|k\\x00y\\x00o\\x00t\\x00o\\x00|f\\x00o\\x00o\\x00|a\\x00d\\x00|b\\x00u\\x00d\\x00a\\x00p\\x00e\\x00s\\x00t\\x00|s\\x00o\\x00l\\x00a\\x00r\\x00|d\\x00v\\x00a\\x00g\\x00|m\\x00z\\x00|a\\x00c\\x00a\\x00d\\x00e\\x00m\\x00y\\x00|p\\x00w\\x00|t\\x00o\\x00y\\x00s\\x00|f\\x00a\\x00i\\x00l\\x00|a\\x00l\\x00|p\\x00h\\x00o\\x00t\\x00o\\x00s\\x00|j\\x00p\\x00|k\\x00r\\x00d\\x00|f\\x00r\\x00l\\x00|w\\x00o\\x00r\\x00k\\x00|p\\x00o\\x00r\\x00n\\x00|w\\x00e\\x00b\\x00s\\x00i\\x00t\\x00e\\x00|b\\x00e\\x00r\\x00l\\x00i\\x00n\\x00|s\\x00a\\x00a\\x00r\\x00l\\x00a\\x00n\\x00d\\x00|v\\x00o\\x00t\\x00i\\x00n\\x00g\\x00|l\\x00g\\x00b\\x00t\\x00|s\\x00o\\x00f\\x00t\\x00w\\x00a\\x00r\\x00e\\x00|c\\x00a\\x00r\\x00e\\x00|c\\x00z\\x00|z\\x00w\\x00|l\\x00v\\x00|d\\x00e\\x00a\\x00l\\x00s\\x00|t\\x00m\\x00|b\\x00u\\x00i\\x00l\\x00d\\x00e\\x00r\\x00s\\x00|c\\x00o\\x00o\\x00k\\x00i\\x00n\\x00g\\x00|d\\x00u\\x00r\\x00b\\x00a\\x00n\\x00|s\\x00o\\x00h\\x00u\\x00|n\\x00c\\x00|w\\x00e\\x00d\\x00d\\x00i\\x00n\\x00g\\x00|b\\x00a\\x00r\\x00|p\\x00h\\x00o\\x00t\\x00o\\x00g\\x00r\\x00a\\x00p\\x00h\\x00y\\x00|b\\x00v\\x00|e\\x00n\\x00g\\x00i\\x00n\\x00e\\x00e\\x00r\\x00|k\\x00n\\x00|c\\x00r\\x00|h\\x00i\\x00p\\x00h\\x00o\\x00p\\x00|o\\x00r\\x00g\\x00a\\x00n\\x00i\\x00c\\x00|r\\x00e\\x00h\\x00a\\x00b\\x00|s\\x00h\\x00i\\x00k\\x00s\\x00h\\x00a\\x00|g\\x00a\\x00r\\x00d\\x00e\\x00n\\x00|i\\x00w\\x00c\\x00|g\\x00g\\x00|m\\x00a\\x00r\\x00r\\x00i\\x00o\\x00t\\x00t\\x00|p\\x00r\\x00o\\x00d\\x00u\\x00c\\x00t\\x00i\\x00o\\x00n\\x00s\\x00|d\\x00i\\x00a\\x00m\\x00o\\x00n\\x00d\\x00s\\x00|c\\x00a\\x00r\\x00t\\x00i\\x00e\\x00r\\x00|f\\x00e\\x00e\\x00d\\x00b\\x00a\\x00c\\x00k\\x00|g\\x00r\\x00a\\x00p\\x00h\\x00i\\x00c\\x00s\\x00|d\\x00o\\x00|s\\x00o\\x00|g\\x00r\\x00e\\x00e\\x00n\\x00|m\\x00e\\x00|p\\x00l\\x00a\\x00c\\x00e\\x00|l\\x00u\\x00x\\x00e\\x00|m\\x00o\\x00r\\x00m\\x00o\\x00n\\x00|v\\x00n\\x00|n\\x00y\\x00c\\x00|f\\x00l\\x00s\\x00m\\x00i\\x00d\\x00t\\x00h\\x00|a\\x00w\\x00|q\\x00p\\x00o\\x00n\\x00|b\\x00f\\x00|j\\x00m\\x00|p\\x00r\\x00a\\x00x\\x00i\\x00|s\\x00g\\x00|c\\x00h\\x00e\\x00a\\x00p\\x00|a\\x00u\\x00t\\x00o\\x00s\\x00|g\\x00i\\x00f\\x00t\\x00|m\\x00m\\x00|r\\x00i\\x00p\\x00|t\\x00r\\x00a\\x00i\\x00n\\x00i\\x00n\\x00g\\x00|y\\x00a\\x00c\\x00h\\x00t\\x00s\\x00|g\\x00w\\x00|v\\x00e\\x00n\\x00t\\x00u\\x00r\\x00e\\x00s\\x00|h\\x00o\\x00r\\x00s\\x00e\\x00|n\\x00t\\x00t\\x00|b\\x00n\\x00|j\\x00e\\x00|a\\x00c\\x00t\\x00i\\x00v\\x00e\\x00|d\\x00i\\x00s\\x00c\\x00o\\x00u\\x00n\\x00t\\x00|y\\x00e\\x00|l\\x00c\\x00|d\\x00o\\x00c\\x00s\\x00|t\\x00z\\x00|l\\x00i\\x00g\\x00h\\x00t\\x00i\\x00n\\x00g\\x00|f\\x00m\\x00|m\\x00o\\x00b\\x00i\\x00|m\\x00o\\x00n\\x00e\\x00y\\x00|m\\x00u\\x00|e\\x00x\\x00p\\x00e\\x00r\\x00t\\x00|c\\x00e\\x00n\\x00t\\x00e\\x00r\\x00|c\\x00o\\x00a\\x00c\\x00h\\x00|p\\x00l\\x00|c\\x00r\\x00e\\x00d\\x00i\\x00t\\x00c\\x00a\\x00r\\x00d\\x00|s\\x00u\\x00p\\x00p\\x00l\\x00y\\x00|a\\x00g\\x00|r\\x00e\\x00v\\x00i\\x00e\\x00w\\x00s\\x00|n\\x00e\\x00t\\x00w\\x00o\\x00r\\x00k\\x00|m\\x00a\\x00i\\x00s\\x00o\\x00n\\x00|c\\x00i\\x00|a\\x00c\\x00c\\x00o\\x00u\\x00n\\x00t\\x00a\\x00n\\x00t\\x00s\\x00|l\\x00k\\x00|z\\x00o\\x00n\\x00e\\x00|c\\x00a\\x00n\\x00o\\x00n\\x00|t\\x00e\\x00c\\x00h\\x00n\\x00o\\x00l\\x00o\\x00g\\x00y\\x00|t\\x00r\\x00|c\\x00o\\x00l\\x00l\\x00e\\x00g\\x00e\\x00|c\\x00y\\x00m\\x00r\\x00u\\x00|n\\x00l\\x00|t\\x00o\\x00k\\x00y\\x00o\\x00|e\\x00n\\x00t\\x00e\\x00r\\x00p\\x00r\\x00i\\x00s\\x00e\\x00s\\x00|c\\x00h\\x00r\\x00o\\x00m\\x00e\\x00|s\\x00u\\x00r\\x00g\\x00e\\x00r\\x00y\\x00|p\\x00t\\x00|r\\x00e\\x00i\\x00s\\x00e\\x00|h\\x00o\\x00s\\x00t\\x00|a\\x00o\\x00|f\\x00l\\x00y\\x00|g\\x00o\\x00v\\x00|r\\x00e\\x00d\\x00|c\\x00a\\x00|b\\x00z\\x00h\\x00|f\\x00l\\x00o\\x00r\\x00i\\x00s\\x00t\\x00|l\\x00s\\x00|g\\x00r\\x00i\\x00p\\x00e\\x00|s\\x00e\\x00r\\x00v\\x00i\\x00c\\x00e\\x00s\\x00|t\\x00j\\x00|a\\x00l\\x00s\\x00a\\x00c\\x00e\\x00)))(?:$|[\\x22\\x27]\\x00|\\W\\x00)"
        ],
        # email addresses
        "email": [
            "(?:^|[^\\w]|['\"])([a-z][_a-z0-9-.]+@[a-z0-9-]{4,}\\.[a-z]{2,})(?:[^\\w]|['\"]|$)",
            "(?:\\x00[\\x22\\x27]|^|\\x00\\W)(\\x00[a-z](?:\\x00[\\x2d\\x2e0-9\\x5fa-z])+\\x00\\x40(?:\\x00[\\x2d0-9a-z])+\\x00\\x2e(?:\\x00[a-z])+)(?:\\x00[\\x22\\x27]|\\x00\\W|$)",
            "(?:^|\\W\\x00|[\\x22\\x27]\\x00)([a-z]\\x00(?:[\\x2d\\x2e0-9\\x5fa-z]\\x00)+\\x40\\x00(?:[\\x2d0-9a-z]\\x00)+\\x2e\\x00(?:[a-z]\\x00)+)(?:\\W\\x00|[\\x22\\x27]\\x00|$)"
        ],
        # filenames (based primarily on extension)
        "filename": [
            "(?:^|[^\\w]|['\"])([A-Za-z0-9-_\\.]+\\.(pdb|exe|dll|bat|sys|hta|htm|html|js|jar|jpg|png|vb|scr|pif|chm|zip|rar|cab|pdf|doc|docx|ppt|pptx|ps1|xls|xlsx|swf|gif))(?:[^\\w]|['\"]|$)",
            "(?:\\x00\\W|^|\\x00[\\x22\\x27])((?:\\x00[\\x2d\\x2e0-9A-Z\\x5fa-z])+\\x00\\x2e((?:\\x00p\\x00d\\x00b|\\x00e\\x00x\\x00e|\\x00j\\x00a\\x00r|\\x00d\\x00o\\x00c|\\x00j\\x00p\\x00g|\\x00z\\x00i\\x00p|\\x00d\\x00o\\x00c\\x00x|\\x00p\\x00d\\x00f|\\x00p\\x00p\\x00t|\\x00h\\x00t\\x00m|\\x00r\\x00a\\x00r|\\x00c\\x00a\\x00b|\\x00x\\x00l\\x00s\\x00x|\\x00p\\x00i\\x00f|\\x00s\\x00y\\x00s|\\x00h\\x00t\\x00a|\\x00s\\x00c\\x00r|\\x00d\\x00l\\x00l|\\x00j\\x00s|\\x00p\\x00n\\x00g|\\x00c\\x00h\\x00m|\\x00b\\x00a\\x00t|\\x00v\\x00b|\\x00g\\x00i\\x00f|\\x00x\\x00l\\x00s|\\x00s\\x00w\\x00f|\\x00p\\x00p\\x00t\\x00x|\\x00p\\x00s\\x001|\\x00h\\x00t\\x00m\\x00l)))(?:\\x00\\W|$|\\x00[\\x22\\x27])",
            "(?:^|[\\x22\\x27]\\x00|\\W\\x00)((?:[\\x2d\\x2e0-9A-Z\\x5fa-z]\\x00)+\\x2e\\x00((?:p\\x00d\\x00b\\x00|d\\x00o\\x00c\\x00|r\\x00a\\x00r\\x00|p\\x00d\\x00f\\x00|h\\x00t\\x00m\\x00l\\x00|p\\x00n\\x00g\\x00|h\\x00t\\x00a\\x00|p\\x00s\\x001\\x00|p\\x00i\\x00f\\x00|c\\x00h\\x00m\\x00|p\\x00p\\x00t\\x00x\\x00|s\\x00w\\x00f\\x00|z\\x00i\\x00p\\x00|e\\x00x\\x00e\\x00|j\\x00p\\x00g\\x00|d\\x00l\\x00l\\x00|x\\x00l\\x00s\\x00x\\x00|p\\x00p\\x00t\\x00|h\\x00t\\x00m\\x00|v\\x00b\\x00|s\\x00y\\x00s\\x00|c\\x00a\\x00b\\x00|g\\x00i\\x00f\\x00|j\\x00a\\x00r\\x00|j\\x00s\\x00|b\\x00a\\x00t\\x00|x\\x00l\\x00s\\x00|s\\x00c\\x00r\\x00|d\\x00o\\x00c\\x00x\\x00)))(?:$|[\\x22\\x27]\\x00|\\W\\x00)"
        ],
        # directory paths, Windows-style
        "filepath": [
            r"""(?:^|[^\w]|['"])([A-Z]:\\[A-Za-z0-9.\\_]+)(?:[^\w]|['"]|$)""",
            r"""(?:^|\x00[^\w]|\x00['"])((\x00[A-Z]\x00:|\x00\\)\x00\\(\x00[A-Za-z0-9.\\_])+)(?:\x00[^\w]|\x00['"]|$)""",
            r"""(?:^|[^\w]\x00|['"]\x00)(([A-Z]\x00:\x00|\\\x00)\\\x00([A-Za-z0-9.\\_]\x00)+)(?:[^\w]\x00|['"]\x00|$)"""
        ],
        # IPv4 addresses
        "ip": [
            "(?:^|[^\\w]|['\"])(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(?:[^\\w]|['\"]|$)",
            "(?:\\x00[\\x22\\x27]|^|\\x00\\W)((?:(((?:\\x002\\x005\\x00[0-5]|(?:\\x00[01])?\\x00[0-9](?:\\x00[0-9])?|\\x002\\x00[0-4]\\x00[0-9]))\\x00\\x2e)){3}(?:\\x002\\x005\\x00[0-5]|(?:\\x00[01])?\\x00[0-9](?:\\x00[0-9])?|\\x002\\x00[0-4]\\x00[0-9]))(?:\\x00[\\x22\\x27]|$|\\x00\\W)",
            "(?:^|[\\x22\\x27]\\x00|\\W\\x00)((?:(((?:2\\x005\\x00[0-5]\\x00|(?:[01]\\x00)?[0-9]\\x00(?:[0-9]\\x00)?|2\\x00[0-4]\\x00[0-9]\\x00))\\x2e\\x00)){3}(?:2\\x005\\x00[0-5]\\x00|(?:[01]\\x00)?[0-9]\\x00(?:[0-9]\\x00)?|2\\x00[0-4]\\x00[0-9]\\x00))(?:\\W\\x00|[\\x22\\x27]\\x00|$)"
        ],
        # Windows Registry paths
        "registry": [
            r"""(?:^|[^\w]|['"])((HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[\\a-z0-9-_]+)(?:[^\w]|['"]|$)""",
            r"""(?:^|\x00[^\w]|\x00['"])((\x00H\x00K\x00L\x00M|\x00H\x00K\x00C\x00U|\x00H\x00K\x00E\x00Y\x00_\x00L\x00O\x00C\x00A\x00L\x00_\x00M\x00A\x00C\x00H\x00I\x00N\x00E|\x00H\x00K\x00E\x00Y\x00_\x00C\x00U\x00R\x00R\x00E\x00N\x00T\x00_\x00U\x00S\x00E\x00R)\x00\\(\x00[\\a-z0-9-_])+)(?:\x00[^\w]|\x00['"]|$)""",
            r"""(?:^|[^\w]\x00|['"]\x00)((H\x00K\x00L\x00M\x00|H\x00K\x00C\x00U\x00|H\x00K\x00E\x00Y\x00_\x00L\x00O\x00C\x00A\x00L\x00_\x00M\x00A\x00C\x00H\x00I\x00N\x00E\x00|\x00H\x00K\x00E\x00Y\x00_\x00C\x00U\x00R\x00R\x00E\x00N\x00T\x00_\x00U\x00S\x00E\x00R\x00)\\\x00([\\a-z0-9-_]\x00)+)(?:[^\w]|['"]|$)""",
        ],
        # URLs
        "url": [
            "(?:^|[^\\w]|['\"])([a-z]{3,}\\:\\/\\/[-_/@#%&+=?.a-z0-9]{12,})(?:[^\\w]|['\"]|$)",
            "(?:\\x00[\\x22\\x27]|^|\\x00\\W)((?:\\x00[a-z]){3,}\\x00\\x3a\\x00\\x2f\\x00\\x2f(?:\\x00[\\x23\\x25\\x26\\x2b\\x2d-9\\x3d\\x3f\\x40\\x5fa-z]){12,})(?:\\x00[\\x22\\x27]|$|\\x00\\W)",
            "(?:\\W\\x00|^|[\\x22\\x27]\\x00)((?:[a-z]\\x00){3,}\\x3a\\x00\\x2f\\x00\\x2f\\x00(?:[\\x23\\x25\\x26\\x2b\\x2d-9\\x3d\\x3f\\x40\\x5fa-z]\\x00){12,})(?:\\W\\x00|$|[\\x22\\x27]\\x00)"
        ],
        # Office document IDs
        "xmpid": [
            "(?:^|[^\\w]|['\"])(xmp\\..id[-: _][-a-f0-9]{32,36})(?:[^\\w]|['\"]|$)",
            "(?:\\x00[\\x22\\x27]|^|\\x00\\W)(\\x00x\\x00m\\x00p\\x00\\x2e\\x00[\\x00-\\xff]\\x00i\\x00d\\x00[\\x20\\x2d\\x3a\\x5f](?:\\x00[\\x2d0-9a-f]){32,36})(?:\\x00[\\x22\\x27]|\\x00\\W|$)",
            "(?:\\W\\x00|^|[\\x22\\x27]\\x00)(x\\x00m\\x00p\\x00\\x2e\\x00[\\x00-\\xff]\\x00i\\x00d\\x00[\\x20\\x2d\\x3a\\x5f]\\x00(?:[\\x2d0-9a-f]\\x00){32,36})(?:\\W\\x00|$|[\\x22\\x27]\\x00)"
        ]
    }

    return IOC_REGEX_SOURCES


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
