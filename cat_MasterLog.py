#!/usr/bin/env python3

# FROM glideinwms/factory/tools/cat_MasterLog.py


import os.path
import sys
import binascii
import gzip
import io
import mmap
import re


### START FROM glideinwms/lib/defaults.py ###

# GlideinWMS has to be compatible across versions running on different Python interpreters
# Python 2 text files are the same as binary files except some newline handling
# and strings are the same as bytes
# To maintain this in Python 3 is possible to write binary files and use for the strings
# any encoding that preserves the bytes (0x80...0xff) through round-tripping from byte
# streams to Unicode and back, latin-1 is the best known of these (more compact).
BINARY_ENCODING = "latin_1"  # valid aliases (case insensitive)  latin-1, latin1, L1, iso-8859-1, 8859


# All strings should be ASCII, so ASCII or latin-1 (256 safe) should be OK
# Anyway M2Crypto uses 'utf_8' to implement AnyStr (union of bytes and str)
BINARY_ENCODING_CRYPTO = "utf_8"  # valid aliases: utf-8, utf8


def force_bytes(instr, encoding=BINARY_ENCODING_CRYPTO):
    """Forces the output to be bytes, encoding the input if it is a unicode string (str)

    AnyStr is str or bytes types

    Args:
        instr (AnyStr): string to be converted
        encoding (str): a valid encoding, utf_8, ascii, latin-1 (iso-8859-1')

    Returns:
        bytes: instr as bytes string

    Raises:
        ValueError: if it detects an improper str conversion (b'' around the string)
    """
    if isinstance(instr, str):
        # raise Exception("ALREADY str!")  # Use this for investigations
        if instr.startswith("b'") and len(instr) > 2 and instr.endswith("'"):
            # This may cause errors with the random strings generated for unit tests, which may start with "b'"
            raise ValueError(
                "Input was improperly converted into string (resulting in b'' characters added): %s" % instr
            )
        # If the encoding is known codecs can be used for more efficiency, e.g. codecs.latin_1_encode(x)[0]
        return instr.encode(encoding)
    return instr

### END FROM glideinwms/lib/defaults.py ###


### START FROM glideinwms/factory/tools/lib/gWftLogParser.py ###

# extract the blob from a glidein log file starting from position
def get_Compressed_raw(log_fname, start_str, start_pos=0):
    SL_START_RE = re.compile(b"%s\nbegin-base64 644 -\n" % force_bytes(start_str, BINARY_ENCODING), re.M | re.DOTALL)
    size = os.path.getsize(log_fname)
    if size == 0:
        return ""  # mmap would fail... and I know I will not find anything anyhow
    with open(log_fname) as fd:
        buf = mmap.mmap(fd.fileno(), size, access=mmap.ACCESS_READ)
        try:
            # first find the header that delimits the log in the file
            start_re = SL_START_RE.search(buf, 0)
            if start_re is None:
                return ""  # no StartLog section
            log_start_idx = start_re.end()

            # find where it ends
            log_end_idx = buf.find(b"\n====", log_start_idx)
            if log_end_idx < 0:  # up to the end of the file
                return buf[log_start_idx:].decode(BINARY_ENCODING)
            else:
                return buf[log_start_idx:log_end_idx].decode(BINARY_ENCODING)
        finally:
            buf.close()


# extract the blob from a glidein log file
def get_Compressed(log_fname, start_str):
    raw_data = get_Compressed_raw(log_fname, start_str)
    if raw_data != "":
        gzip_data = binascii.a2b_base64(raw_data)
        del raw_data
        data_fd = gzip.GzipFile(fileobj=io.BytesIO(gzip_data))
        data = data_fd.read().decode(BINARY_ENCODING)
    else:
        data = raw_data
    return data


# extract the Condor Log from a glidein log file
# condor_log_id should be something like "StartdLog"
def get_CondorLog(log_fname, condor_log_id):
    start_str = "^%s\n======== gzip . uuencode =============" % condor_log_id
    return get_Compressed(log_fname, start_str)

### END FROM glideinwms/factory/tools/lib/gWftLogParser.py ###


USAGE = "Usage: cat_MasterLog.py [-monitor] <logname>"


def main():
    try:
        if sys.argv[1] == "-monitor":
            fname = sys.argv[2]
            condor_log_id = "MasterLog.monitor"
        else:
            fname = sys.argv[1]
            condor_log_id = "MasterLog"

        print(get_CondorLog(fname, condor_log_id))
    except Exception:
        sys.stderr.write("%s\n" % USAGE)
        sys.exit(1)


if __name__ == "__main__":
    main()
