#!/usr/bin/env python
################################################################################
# yubi_goog.py - google authenticator via yubikey
#
# Use --generate to generate OTPs given a base 32 secret key (from google)
# Use --yubi to send a challenge to the yubikey to generate OTPs
# Use --convert-secret to convert the google secret into hex
#
# author: Casey Link <unnamedrambler@gmail.com>
################################################################################

import base64
import re
import binascii
import time
import sys
import subprocess
import hashlib
import hmac
import struct

ADJACENT_INTERVALS = 3 # generate 3 OTPs
TIME_STEP = 30 # default as per TOTP spec

# supporting py2 and py3 sucks
IS_PY3 = sys.version_info[0] == 3

def mangle_hash(h):
    if IS_PY3:
        offset = h[-1] & 0x0F
    else:
        offset = ord(h[-1]) & 0x0F
    truncated_hash = h[offset:offset+4]

    code = struct.unpack(">L", truncated_hash)[0]
    code &= 0x7FFFFFFF;
    code %= 1000000;

    return '{0:06d}'.format(code)

def totp(secret, tm):
    bin_key = binascii.unhexlify(secret)
    h = hmac.new(bin_key, tm, hashlib.sha1).digest()

    return mangle_hash(h)

def generate_challenges(intervals = ADJACENT_INTERVALS):
    """
    intervals: must be odd number

    generates intervals-number total challenges. used to
    workaround clock skew.
    """
    challenges = []
    t = int(time.time())
    for ix in range(0-int(intervals/2), int(intervals/2)+1):
        tm = (t + TIME_STEP*ix)/TIME_STEP
        tm = struct.pack('>q', int(tm))
        challenges.append(tm)
    return challenges

def decode_secret(secret):
    """
    Decodes the base32 string google provides" to hex
    """
    # remove spaces and uppercase
    secret = re.sub(r'\s', '', secret).upper()
    secret = secret.encode('ascii')
    secret = base64.b32decode(secret)
    return binascii.hexlify(secret)

def get_secret():
    """
    Read secret from user
    """

    sys.stderr.write("Google key: ")
    if IS_PY3:
        google_key = input()
    else:
        google_key = raw_input()
    return decode_secret(google_key)

def convert_secret():
    secret = get_secret()
    print(secret.decode().ljust(40, '0'))

def generate():
    # convert secret to hex
    secret = get_secret()
    # now, and 30 seconds ahead and behind
    for chal in generate_challenges():
        print("OTP: %s" %( totp(secret, chal) ))


def yubi(use_sudo):
    for chal in generate_challenges(0):
        chal = binascii.hexlify(chal)
        cmd = []
        if use_sudo:
            cmd = ['sudo']
        cmd.append('ykchalresp')
        cmd.append('-2x')
        cmd.append(chal)
        if hasattr(subprocess, "check_output"):
            resp = subprocess.check_output(cmd).strip()
        else:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
            out, err = proc.communicate()
            if not isinstance(out, basestring):
                raise ValueError("Command {0} returned {1!r}."
                                 .format(" ".join(cmd), out))
            resp = out.strip()
        print("%s" %(mangle_hash(binascii.unhexlify(resp))))

def error():
    print("Valid opts: --generate, --yubi, --yubi-no-sudo, or --convert-secret")

if __name__ == "__main__":
    if len(sys.argv) <= 1:
        yubi()
        sys.exit(1)
    if sys.argv[1] == "--generate":
        generate()
    elif sys.argv[1] == "--yubi":
        yubi(True)
    elif sys.argv[1] == "--yubi-no-sudo":
        yubi(False)
    elif sys.argv[1] == "--convert-secret":
        convert_secret()
    else:
        error()
        sys.exit(1)

