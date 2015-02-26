#! /usr/bin/env python3

import sys
import hmac
import base64
import getpass
import string
import re

PREFIX = '@@'


def str_ROL(s, n):
    n = n % len(s)
    return s[n:] + s[:n]


def extract_domain(uri):
    return uri  # TODO


def apply_constraints(digest, size, alnum=False):
    result = digest[:size-4]  # leave room for some extra characters
    extras = list(reversed(digest[size-4:]))

    def cond_add_extra(f, candidates):
        n = ord(extras.pop()) if extras else 0
        if any(f(x) for x in result):
            return chr(n)
        else:
            return candidates[n % len(candidates)]

    result += cond_add_extra(str.isupper, string.ascii_uppercase)
    result += cond_add_extra(str.islower, string.ascii_lowercase)
    result += cond_add_extra(str.isdigit, string.digits)
    if re.search('\W', result) and not alnum:
        result += extras.pop() if extras else chr(0)
    else:
        result += '+'
    if alnum:
        while re.search('\W', result):
            c = cond_add_extra(lambda x: False, string.ascii_uppercase)
            result = re.sub('\W', c, result, count=1)
    return str_ROL(result, ord(extras.pop()) if extras else 0)


def pwdhash(domain, password):
    domain = domain.encode('utf-8')
    password = password.encode('utf-8')
    digest = hmac.new(password, domain, 'md5').digest()
    b64digest = base64.b64encode(digest).decode("utf-8")[:-2]  # remove padding
    size = len(PREFIX) + len(password)
    return apply_constraints(b64digest, size, password.isalnum())


def main():
    if len(sys.argv) != 2:
        sys.exit("Usage: pwdhash domain")
    domain = extract_domain(sys.argv[1])
    password = getpass.getpass()
    print(pwdhash(domain, password), '')

if __name__ == '__main__':
    main()
