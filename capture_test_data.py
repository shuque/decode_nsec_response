#!/usr/bin/env python3

"""Capture DNS wire-format responses for the test suite.

Queries each test case via DoH to Cloudflare and saves the raw wire
bytes to testdata/. Re-run this script to refresh test data when
intentionally updating test cases.
"""

import os
import dns.name
import dns.query
import dns.message
import dns.flags

DOH_URL = "https://cloudflare-dns.com/dns-query"
TESTDATA_DIR = os.path.join(os.path.dirname(__file__), "testdata")

TEST_CASES = [
    ("nsec_nodata",              "nseczone.huque.com.",                          "TLSA"),
    ("nsec_nxdomain",            "nonexistent.nseczone.huque.com.",              "A"),
    ("nsec_nxdomain_root",       "foobar.",                                      "A"),
    ("nsec_cdoe",                "nonexistent.cloudflare.com.",                   "A"),
    ("nsec3_nodata",             "dnskensa.com.",                                 "AAAA"),
    ("nsec3_nxdomain",           "foo.nxd123.salesforce.com.",                    "A"),
    ("nsec3_wildcard",           "foo.bar.wild.dnskensa.com.",                    "A"),
    ("nsec3_wildcard_nodata",    "foo.bar.wild.dnskensa.com.",                    "AAAA"),
    ("cname_nodata",             "www.huque.com.",                                "TLSA"),
    ("wildcard_cname_nodata",    "12345asdfasfadf.horoscope-divination.com.",     "AFSDB"),
    ("nsec3_nxdomain_circular",  "foo.kalebet1363.com.",                          "AAAA"),
    ("dangling_cname",           "danglingcname.dnskensa.com.",                    "A"),
]


def capture():
    os.makedirs(TESTDATA_DIR, exist_ok=True)
    for name, qname_str, qtype in TEST_CASES:
        print(f"Capturing {name}: {qname_str} {qtype} ... ", end="", flush=True)
        qname = dns.name.from_text(qname_str)
        q = dns.message.make_query(qname, qtype, want_dnssec=True)
        q.flags |= dns.flags.AD
        response = dns.query.https(q, DOH_URL)
        path = os.path.join(TESTDATA_DIR, f"{name}.wire")
        with open(path, "wb") as f:
            f.write(response.to_wire())
        print(f"OK ({len(response.to_wire())} bytes)")
    print(f"\nAll {len(TEST_CASES)} responses saved to {TESTDATA_DIR}/")


if __name__ == "__main__":
    capture()
