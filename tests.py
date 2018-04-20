import unittest

import iocextract

# Helper functions
def _wrap_spaces(content):
    return '  {c}  '.format(c=content)

def _wrap_tabs(content):
    return '\t\t{c}\t\t'.format(c=content)

def _wrap_newlines(content):
    return '\r\n{c}\r\n'.format(c=content)

def _wrap_words(content):
    return 'words{c}words'.format(c=content)

def _wrap_nonwords(content):
    return '.!@..{c}!@#-'.format(c=content)


# Tests
class TestExtractors(unittest.TestCase):

    def test_corpus_results(self):
        in_data = open('test_data/input.txt', 'r').read()
        valid_results = open('test_data/valid.txt', 'r').read().splitlines()
        invalid_results = open('test_data/invalid.txt', 'r').read().splitlines()

        out_data = list(iocextract.extract_iocs(in_data))

        for expected in valid_results:
            self.assertIn(expected, out_data)

        for unexpected in invalid_results:
            self.assertNotIn(unexpected, out_data)

    def test_md5_extract(self):
        content = '68b329da9893e34099c7d8ad5cb9c940'

        self.assertEquals(list(iocextract.extract_md5_hashes(content))[0], content)
        self.assertEquals(list(iocextract.extract_md5_hashes(_wrap_spaces(content)))[0], content)
        self.assertEquals(list(iocextract.extract_md5_hashes(_wrap_tabs(content)))[0], content)
        self.assertEquals(list(iocextract.extract_md5_hashes(_wrap_newlines(content)))[0], content)
        self.assertEquals(list(iocextract.extract_md5_hashes(_wrap_words(content)))[0], content)
        self.assertEquals(list(iocextract.extract_md5_hashes(_wrap_nonwords(content)))[0], content)

    def test_sha1_extract(self):
        content = 'adc83b19e793491b1c6ea0fd8b46cd9f32e592fc'

        self.assertEquals(list(iocextract.extract_sha1_hashes(content))[0], content)
        self.assertEquals(list(iocextract.extract_sha1_hashes(_wrap_spaces(content)))[0], content)
        self.assertEquals(list(iocextract.extract_sha1_hashes(_wrap_tabs(content)))[0], content)
        self.assertEquals(list(iocextract.extract_sha1_hashes(_wrap_newlines(content)))[0], content)
        self.assertEquals(list(iocextract.extract_sha1_hashes(_wrap_words(content)))[0], content)
        self.assertEquals(list(iocextract.extract_sha1_hashes(_wrap_nonwords(content)))[0], content)

    def test_sha256_extract(self):
        content = '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b'

        self.assertEquals(list(iocextract.extract_sha256_hashes(content))[0], content)
        self.assertEquals(list(iocextract.extract_sha256_hashes(_wrap_spaces(content)))[0], content)
        self.assertEquals(list(iocextract.extract_sha256_hashes(_wrap_tabs(content)))[0], content)
        self.assertEquals(list(iocextract.extract_sha256_hashes(_wrap_newlines(content)))[0], content)
        self.assertEquals(list(iocextract.extract_sha256_hashes(_wrap_words(content)))[0], content)
        self.assertEquals(list(iocextract.extract_sha256_hashes(_wrap_nonwords(content)))[0], content)

    def test_sha512_extract(self):
        content = 'be688838ca8686e5c90689bf2ab585cef1137c999b48c70b92f67a5c34dc15697b5d11c982ed6d71be1e1e7f7b4e0733884aa97c3f7a339a8ed03577cf74be09'

        self.assertEquals(list(iocextract.extract_sha512_hashes(content))[0], content)
        self.assertEquals(list(iocextract.extract_sha512_hashes(_wrap_spaces(content)))[0], content)
        self.assertEquals(list(iocextract.extract_sha512_hashes(_wrap_tabs(content)))[0], content)
        self.assertEquals(list(iocextract.extract_sha512_hashes(_wrap_newlines(content)))[0], content)
        self.assertEquals(list(iocextract.extract_sha512_hashes(_wrap_words(content)))[0], content)
        self.assertEquals(list(iocextract.extract_sha512_hashes(_wrap_nonwords(content)))[0], content)

    def test_md5_not_in_shax(self):
        content = 'adc83b19e793491b1c6ea0fd8b46cd9f32e592fc'

        self.assertEquals(len(list(iocextract.extract_md5_hashes(content))), 0)
        self.assertEquals(len(list(iocextract.extract_md5_hashes(_wrap_spaces(content)))), 0)
        self.assertEquals(len(list(iocextract.extract_md5_hashes(_wrap_tabs(content)))), 0)
        self.assertEquals(len(list(iocextract.extract_md5_hashes(_wrap_newlines(content)))), 0)
        self.assertEquals(len(list(iocextract.extract_md5_hashes(_wrap_words(content)))), 0)
        self.assertEquals(len(list(iocextract.extract_md5_hashes(_wrap_nonwords(content)))), 0)

        content = '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b'

        self.assertEquals(len(list(iocextract.extract_md5_hashes(content))), 0)
        self.assertEquals(len(list(iocextract.extract_md5_hashes(_wrap_spaces(content)))), 0)
        self.assertEquals(len(list(iocextract.extract_md5_hashes(_wrap_tabs(content)))), 0)
        self.assertEquals(len(list(iocextract.extract_md5_hashes(_wrap_newlines(content)))), 0)
        self.assertEquals(len(list(iocextract.extract_md5_hashes(_wrap_words(content)))), 0)
        self.assertEquals(len(list(iocextract.extract_md5_hashes(_wrap_nonwords(content)))), 0)

        content = 'be688838ca8686e5c90689bf2ab585cef1137c999b48c70b92f67a5c34dc15697b5d11c982ed6d71be1e1e7f7b4e0733884aa97c3f7a339a8ed03577cf74be09'

        self.assertEquals(len(list(iocextract.extract_md5_hashes(content))), 0)
        self.assertEquals(len(list(iocextract.extract_md5_hashes(_wrap_spaces(content)))), 0)
        self.assertEquals(len(list(iocextract.extract_md5_hashes(_wrap_tabs(content)))), 0)
        self.assertEquals(len(list(iocextract.extract_md5_hashes(_wrap_newlines(content)))), 0)
        self.assertEquals(len(list(iocextract.extract_md5_hashes(_wrap_words(content)))), 0)
        self.assertEquals(len(list(iocextract.extract_md5_hashes(_wrap_nonwords(content)))), 0)

    def test_sha1_not_in_shaxxx(self):
        content = '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b'

        self.assertEquals(len(list(iocextract.extract_sha1_hashes(content))), 0)
        self.assertEquals(len(list(iocextract.extract_sha1_hashes(_wrap_spaces(content)))), 0)
        self.assertEquals(len(list(iocextract.extract_sha1_hashes(_wrap_tabs(content)))), 0)
        self.assertEquals(len(list(iocextract.extract_sha1_hashes(_wrap_newlines(content)))), 0)
        self.assertEquals(len(list(iocextract.extract_sha1_hashes(_wrap_words(content)))), 0)
        self.assertEquals(len(list(iocextract.extract_sha1_hashes(_wrap_nonwords(content)))), 0)

        content = 'be688838ca8686e5c90689bf2ab585cef1137c999b48c70b92f67a5c34dc15697b5d11c982ed6d71be1e1e7f7b4e0733884aa97c3f7a339a8ed03577cf74be09'

        self.assertEquals(len(list(iocextract.extract_sha1_hashes(content))), 0)
        self.assertEquals(len(list(iocextract.extract_sha1_hashes(_wrap_spaces(content)))), 0)
        self.assertEquals(len(list(iocextract.extract_sha1_hashes(_wrap_tabs(content)))), 0)
        self.assertEquals(len(list(iocextract.extract_sha1_hashes(_wrap_newlines(content)))), 0)
        self.assertEquals(len(list(iocextract.extract_sha1_hashes(_wrap_words(content)))), 0)
        self.assertEquals(len(list(iocextract.extract_sha1_hashes(_wrap_nonwords(content)))), 0)

    def test_sha256_not_in_sha512(self):
        content = 'be688838ca8686e5c90689bf2ab585cef1137c999b48c70b92f67a5c34dc15697b5d11c982ed6d71be1e1e7f7b4e0733884aa97c3f7a339a8ed03577cf74be09'

        self.assertEquals(len(list(iocextract.extract_sha256_hashes(content))), 0)
        self.assertEquals(len(list(iocextract.extract_sha256_hashes(_wrap_spaces(content)))), 0)
        self.assertEquals(len(list(iocextract.extract_sha256_hashes(_wrap_tabs(content)))), 0)
        self.assertEquals(len(list(iocextract.extract_sha256_hashes(_wrap_newlines(content)))), 0)
        self.assertEquals(len(list(iocextract.extract_sha256_hashes(_wrap_words(content)))), 0)
        self.assertEquals(len(list(iocextract.extract_sha256_hashes(_wrap_nonwords(content)))), 0)

    def test_hash_extract(self):
        content = """
            68b329da9893e34099c7d8ad5cb9c940
            adc83b19e793491b1c6ea0fd8b46cd9f32e592fc
            01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b
            be688838ca8686e5c90689bf2ab585cef1137c999b48c70b92f67a5c34dc15697b5d11c982ed6d71be1e1e7f7b4e0733884aa97c3f7a339a8ed03577cf74be09
        """

        processed = list(iocextract.extract_hashes(content))

        self.assertEquals(len(processed), 4)
        self.assertEquals(processed[0], '68b329da9893e34099c7d8ad5cb9c940')

        processed = list(iocextract.extract_iocs(content))

        self.assertEquals(len(processed), 4)
        self.assertEquals(processed[0], '68b329da9893e34099c7d8ad5cb9c940')

    def test_email_extract(self):
        content_list = [
            'myuser@example.com',
            'myuser+some@example.com',
            'my.user@example.com',
            'my.user.24@example.com',
            'my.u+ser24@example.com',
            'myuser@exam.ple.com',
            'my.u+ser24@exa.mple24.tl',
            'my_user@example.co',
            'a@a.co',
            'a@127.0.0.1',
        ]

        for content in content_list:
            self.assertEquals(list(iocextract.extract_emails(content))[0], content)
            self.assertEquals(list(iocextract.extract_emails(_wrap_spaces(content)))[0], content)
            self.assertEquals(list(iocextract.extract_emails(_wrap_tabs(content)))[0], content)
            self.assertEquals(list(iocextract.extract_emails(_wrap_newlines(content)))[0], content)

        invalid_list = [
            '@a.co',
            'myuser@',
            '@',
            # don't extract non-fqdn emails
            'a@a',
        ]

        for content in invalid_list:
            self.assertEquals(len(list(iocextract.extract_emails(content))), 0)
            self.assertEquals(len(list(iocextract.extract_emails(_wrap_spaces(content)))), 0)
            self.assertEquals(len(list(iocextract.extract_emails(_wrap_tabs(content)))), 0)
            self.assertEquals(len(list(iocextract.extract_emails(_wrap_newlines(content)))), 0)

    def test_email_included_in_iocs(self):
        content = 'test@example.com'
        self.assertEquals(list(iocextract.extract_iocs(content))[0], content)

    def test_ipv4_extract(self):
        content_list = [
            '127.0.0.1',
            '192.168.255.255',
            '1.1.1.1',
            '1[.]1[.]1[.]1',
            '1(.)1(.)1(.)1',
            '111[.]111[.]111[.]111',
            '111[.]111.111[.]111',
            '111[.111.]111[.111',
            '0.0.0.0',
            '100.100.100.100',
            '200.200.200.200',
            '200.201.210.209',
            '105.105.105.105',
            '250.250.250.250',
            '26.26.26.26',
            '255.255.255.255',
        ]

        for content in content_list:
            self.assertEquals(list(iocextract.extract_ipv4s(content))[0], content)
            self.assertEquals(list(iocextract.extract_ipv4s(_wrap_spaces(content)))[0], content)
            self.assertEquals(list(iocextract.extract_ipv4s(_wrap_tabs(content)))[0], content)
            self.assertEquals(list(iocextract.extract_ipv4s(_wrap_newlines(content)))[0], content)
            self.assertEquals(list(iocextract.extract_ipv4s(_wrap_words(content)))[0], content)
            self.assertEquals(list(iocextract.extract_ipv4s(_wrap_nonwords(content)))[0], content)

        invalid_list = [
            '192.168.1',
            '192.168.a.1',
            '11111.1111.1111.1111',
        ]

        for content in invalid_list:
            self.assertEquals(len(list(iocextract.extract_ipv4s(content))), 0)
            self.assertEquals(len(list(iocextract.extract_ipv4s(_wrap_spaces(content)))), 0)
            self.assertEquals(len(list(iocextract.extract_ipv4s(_wrap_tabs(content)))), 0)
            self.assertEquals(len(list(iocextract.extract_ipv4s(_wrap_newlines(content)))), 0)

    def test_ipv4_included_in_ips(self):
        content = '127.0.0.1'
        self.assertEquals(list(iocextract.extract_ips(content))[0], content)

    def test_ipv4_included_in_iocs(self):
        content = '127.0.0.1'
        self.assertEquals(list(iocextract.extract_iocs(content))[0], content)

    def test_url_extract(self):
        domain_list = [
            'example.com',
            'a.a',
            '192.168.1.1',
            'a[.]a',
            'example[.]com',
            'example[.com',
            'example',
            '192[.]168.1.1',
            '192[.168.1.1',
            'asda.asdasdas.acasc.example.com',
            '12.123.asdas.com',
            'example\u1111com',
            'example .com',
        ]

        prepend_list = [
            "http://",
            "hxxp://",
            "https://",
            "hxxps://",
            "tcp://",
            "ftp://",
            "http__",
            "https__",
            "ftx://",
            "udp://",
            "sftp://",
            "ftps://",
            "http:// ",
            "HXXP://",
        ]

        append_list = [
            '/test.com?asd=qwe%20_#zxc',
            '/test.com?asd=qwe#zxc',
            '/test.com',
            '/test',
            '/',
            '//',
            '',
            ' /test/path',
        ]

        content_list = []
        for domain in domain_list:
            for prepend in prepend_list:
                for append in append_list:
                    content_list.append(prepend + domain + append)

        content_list += [
            'example[.]com',
            'example [.] com',
            'a [.] b [.] example [.] com',
            'a[.]b[.]example[.]com',
            'a[.]b [.] example[.]com',
            'a[.]b[.] example[.]com',
            'example[.]com/path!#&%?+='
            'example(.)com/test',
            'example (.) com/test',
        ]

        for content in content_list:
            self.assertEquals(list(iocextract.extract_urls(content))[0], content)
            self.assertEquals(list(iocextract.extract_urls(_wrap_spaces(content)))[0], content)
            self.assertEquals(list(iocextract.extract_urls(_wrap_tabs(content)))[0], content)
            self.assertEquals(list(iocextract.extract_urls(_wrap_newlines(content)))[0], content)

        invalid_list = [
            # can't differentiate this from e.g. file.pdf
            'domain.com',
        ]

        for content in invalid_list:
            self.assertEquals(len(list(iocextract.extract_urls(content))), 0)
            self.assertEquals(len(list(iocextract.extract_urls(_wrap_spaces(content)))), 0)
            self.assertEquals(len(list(iocextract.extract_urls(_wrap_tabs(content)))), 0)
            self.assertEquals(len(list(iocextract.extract_urls(_wrap_newlines(content)))), 0)

    def test_url_included_in_iocs(self):
        content = 'http://domain.com/test'
        self.assertEquals(list(iocextract.extract_iocs(content))[0], content)

    def test_ipv6_extract(self):

        content_list = [
            '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
            '2001:db8:85a3:0:0:8a2e:370:7334',
            '2001:db8:85a3::8a2e:370:7334',
            '2001:db8::1',
            '2001:0db8::0001',
            '2001:db8:0:0:0:0:2:1',
            '2001:db8::2:1',
            '2001:db8:0000:1:1:1:1:1',
            '2001:db8:0:1:1:1:1:1',
            '2001:db8::1:0:0:1',
            '2001:db8:1234:0000:0000:0000:0000:0000',
            '2001:db8:1234:ffff:ffff:ffff:ffff:ffff',
            'fe80::1ff:fe23:4567:890a',
        ]

        for content in content_list:
            self.assertEquals(list(iocextract.extract_ipv6s(content))[0], content)
            self.assertEquals(list(iocextract.extract_ipv6s(_wrap_spaces(content)))[0], content)
            self.assertEquals(list(iocextract.extract_ipv6s(_wrap_tabs(content)))[0], content)
            self.assertEquals(list(iocextract.extract_ipv6s(_wrap_newlines(content)))[0], content)
            self.assertEquals(list(iocextract.extract_ipv6s(_wrap_nonwords(content)))[0], content)

        invalid_list = [
            '192.168.1',
            # Not caught
            '::1',
            '::',
        ]

        for content in invalid_list:
            self.assertEquals(len(list(iocextract.extract_ipv6s(content))), 0)
            self.assertEquals(len(list(iocextract.extract_ipv6s(_wrap_spaces(content)))), 0)
            self.assertEquals(len(list(iocextract.extract_ipv6s(_wrap_tabs(content)))), 0)
            self.assertEquals(len(list(iocextract.extract_ipv6s(_wrap_newlines(content)))), 0)

    def test_ipv6_included_in_ips(self):
        content = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
        self.assertEquals(list(iocextract.extract_ips(content))[0], content)

    def test_ipv6_included_in_iocs(self):
        content = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
        self.assertEquals(list(iocextract.extract_iocs(content))[0], content)

    def test_yara_extract(self):

        content_list = [
            'rule testRule { condition: true }',
            'rule testRule {\r\n    condition: true\r\n}',
            'rule testRule {\r\n\r\n    condition: true\r\n\r\n\r\n}',
            """rule silent_banker : banker
            {
                meta:
                    description = "This is just an example"
                    thread_level = 3
                    in_the_wild = true
                strings:
                    $a = {6A 40 68 00 30 00 00 6A 14 8D 91}
                    $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
                    $c = "UVODFRYSIHLNWPEJXQZAKCBGMT"
                condition:
                    $a or $b or $c
            }""",
        ]

        for content in content_list:
            self.assertEquals(list(iocextract.extract_yara_rules(content))[0], content)
            self.assertEquals(list(iocextract.extract_yara_rules(_wrap_spaces(content)))[0], content)
            self.assertEquals(list(iocextract.extract_yara_rules(_wrap_tabs(content)))[0], content)
            self.assertEquals(list(iocextract.extract_yara_rules(_wrap_newlines(content)))[0], content)

        invalid_list = [
            'rule testRule { conditio: true }',
            'rule testRule { condition true }',
            'rule testRule { condition: true ',
            'ule testRule { condition: true }',
            'rule testRule  condition: true }',
        ]

        for content in invalid_list:
            self.assertEquals(len(list(iocextract.extract_yara_rules(content))), 0)
            self.assertEquals(len(list(iocextract.extract_yara_rules(_wrap_spaces(content)))), 0)
            self.assertEquals(len(list(iocextract.extract_yara_rules(_wrap_tabs(content)))), 0)
            self.assertEquals(len(list(iocextract.extract_yara_rules(_wrap_newlines(content)))), 0)

    def test_yara_included_in_iocs(self):
        content = 'rule testRule { condition: true }'
        self.assertEquals(list(iocextract.extract_iocs(content))[0], content)

    def test_refang_ipv4(self):
        content_list = [
            '111.111.111.111',
            '111[.]111[.]111[.]111',
            '111(.)111(.)111(.)111',
            '111[.]111[.]111[.]111',
            '111[.]111.111[.]111',
            '111[.111.]111[.111',
        ]

        for content in content_list:
            self.assertEquals(list(iocextract.extract_ipv4s(content, refang=True))[0], '111.111.111.111')
            self.assertEquals(iocextract.refang_ipv4(content), '111.111.111.111')

    def test_refang_url(self):
        content_list = [
            'http://example.com/test',
            'http:// example .com /test',
            'http://example[.]com/test',
            'http://example[.]com[/]test',
            'http://example(.)com(/)test',
            'http://example[dot]com/test',
            'hxxp://example.com/test',
            'example [.] com/test',
            'example(.)com/test',
            'hxxp://example[.com/test',
            'hxxp://example.]com/test',
            'hxxp://exampledot]com/test',
            'hxxp://example[dotcom/test',
            'hxxp://example.com[/test',
            'http__example.com/test',
        ]

        for content in content_list:
            self.assertEquals(list(iocextract.extract_urls(content, refang=True))[0], 'http://example.com/test')
            self.assertEquals(iocextract.refang_url(content), 'http://example.com/test')

        # IPv6 works as expected
        content = 'http://[2001:db8:85a3:0:0:8a2e:370:7334]:80/test'
        self.assertEquals(iocextract.refang_url(content), content)
        self.assertEquals(list(iocextract.extract_urls(content, refang=True))[0], content)

    def test_url_extraction_handles_punctuation(self):
        self.assertEquals(list(iocextract.extract_urls('http://example.com!'))[0], 'http://example.com')
        self.assertEquals(list(iocextract.extract_urls('http://example.com!!!!'))[0], 'http://example.com')
        self.assertEquals(list(iocextract.extract_urls('http://example.com/!!!!'))[0], 'http://example.com/')
        self.assertEquals(list(iocextract.extract_urls('http://example.com/!'))[0], 'http://example.com/')
        self.assertEquals(list(iocextract.extract_urls('http://example.com/?'))[0], 'http://example.com/')
        self.assertEquals(list(iocextract.extract_urls('http://example.com/!path'))[0], 'http://example.com/!path')
        self.assertEquals(list(iocextract.extract_urls('http://example.com/?path'))[0], 'http://example.com/?path')
        self.assertEquals(list(iocextract.extract_urls('http://example.com?'))[0], 'http://example.com')
        self.assertEquals(list(iocextract.extract_urls('http://example.com.'))[0], 'http://example.com')
        self.assertEquals(list(iocextract.extract_urls('http://example.com/?q=test???'))[0], 'http://example.com/?q=test')
        self.assertEquals(list(iocextract.extract_urls('http://example.com/ ...'))[0], 'http://example.com/')

        self.assertEquals(list(iocextract.extract_urls('example[.]com!'))[0], 'example[.]com')
        self.assertEquals(list(iocextract.extract_urls('example[.]com!!!!'))[0], 'example[.]com')
        self.assertEquals(list(iocextract.extract_urls('example[.]com/!!!!'))[0], 'example[.]com/')
        self.assertEquals(list(iocextract.extract_urls('example[.]com/!'))[0], 'example[.]com/')
        self.assertEquals(list(iocextract.extract_urls('example[.]com/?'))[0], 'example[.]com/')
        self.assertEquals(list(iocextract.extract_urls('example[.]com/!path'))[0], 'example[.]com/!path')
        self.assertEquals(list(iocextract.extract_urls('example[.]com/?path'))[0], 'example[.]com/?path')
        self.assertEquals(list(iocextract.extract_urls('example[.]com?'))[0], 'example[.]com')
        self.assertEquals(list(iocextract.extract_urls('example[.]com.'))[0], 'example[.]com')
        self.assertEquals(list(iocextract.extract_urls('example[.]com/?q=test???'))[0], 'example[.]com/?q=test')
        self.assertEquals(list(iocextract.extract_urls('example[.]com/ ...'))[0], 'example[.]com/')
