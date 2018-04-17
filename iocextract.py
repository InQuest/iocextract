import re

#get basic url format counting a few obfuscation techniques
GENERIC_URL_RE = re.compile(r"[ht]\w\w?ps?[\:\_]\/\/\S+(?=\s|$)")
#get some obfuscated ip addresses
IP_RE = re.compile(r"(\d{1,3}\[?\.\]?\d{1,3}\[?\.\]?\d{1,3}\[?\.\]?\d{1,3}(?:\/\d{1,3})?)")

EMAIL_RE = re.compile(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")
MD5_RE = re.compile(r"(\b[a-fA-F\d]{32})\b")
SHA1_RE = re.compile(r"\b([a-fA-F\d]{40})\b")
SHA256_RE = re.compile(r"\b([a-fA-F\d]{64})\b")
SHA512_RE = re.compile(r"(\b[a-fA-F\d]{128})\b")

def extract_info(data, urls=False, ips=False, emails=False, hashes=False):
    """
    Gets desired data from string using various regex
    """

    #if select nothing then run all
    if not urls and not ips and not hashes and not emails:
        urls = ips = hashes = emails = True

    if urls:
        for url in GENERIC_URL_RE.findall(data):
            yield(url)

    if ips:
        for ip in IP_RE.findall(data):
            yield(ip)

    if emails:
        for email in EMAIL_RE.findall(data):
            yield(email)

    if hashes:
        for md5 in MD5_RE.findall(data):
            yield(md5)
        for sha1 in SHA1_RE.findall(data):
            yield(sha1)
        for sha256 in SHA256_RE.findall(data):
            yield(sha256)
        for sha512 in SHA512_RE.findall(data):
            yield(sha512)
