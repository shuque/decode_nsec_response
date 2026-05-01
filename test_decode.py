#!/usr/bin/env python3

"""Test suite for decode_nsec_response.py using canned wire-format responses.

Run: python3 -m unittest test_decode -v
     python3 -m pytest test_decode.py -v   (if pytest is installed)
"""

import io
import os
import sys
import unittest
import contextlib

import dns.message
import dns.name

sys.path.insert(0, os.path.dirname(__file__))
from decode_nsec_response import decode_response

TESTDATA_DIR = os.path.join(os.path.dirname(__file__), "testdata")


def run_decode(wire_file, qname_str, qtype_str):
    """Load a canned response and return decode_response output."""
    path = os.path.join(TESTDATA_DIR, wire_file)
    with open(path, "rb") as f:
        response = dns.message.from_wire(f.read())
    qname = dns.name.from_text(qname_str)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        decode_response(qname, qtype_str, response)
    return buf.getvalue()


def assert_lines_in_order(test_case, output, expected_lines):
    """Assert that each expected line appears in output, in order."""
    pos = 0
    for line in expected_lines:
        idx = output.find(line, pos)
        test_case.assertGreaterEqual(
            idx, 0,
            f"Expected line not found (or out of order):\n"
            f"  {line!r}\n"
            f"Remaining output from position {pos}:\n"
            f"  {output[pos:pos+300]!r}"
        )
        pos = idx + len(line)


class TestNSECNodata(unittest.TestCase):
    def test_classification(self):
        out = run_decode("nsec_nodata.wire", "nseczone.huque.com.", "TLSA")
        self.assertIn("NODATA: nseczone.huque.com. exists but has no TLSA record.", out)

    def test_nsec_match(self):
        out = run_decode("nsec_nodata.wire", "nseczone.huque.com.", "TLSA")
        assert_lines_in_order(self, out, [
            "NSEC: nseczone.huque.com. -> bar.nseczone.huque.com.",
            "Role: Matches the queried name (nseczone.huque.com.)",
            "does not include TLSA",
        ])

    def test_no_nxdomain(self):
        out = run_decode("nsec_nodata.wire", "nseczone.huque.com.", "TLSA")
        self.assertNotIn("NXDOMAIN", out)

    def test_no_answer_section(self):
        out = run_decode("nsec_nodata.wire", "nseczone.huque.com.", "TLSA")
        self.assertNotIn("Answer section:", out)


class TestNSECNxdomain(unittest.TestCase):
    def test_classification(self):
        out = run_decode("nsec_nxdomain.wire",
                         "nonexistent.nseczone.huque.com.", "A")
        self.assertIn("NXDOMAIN: nonexistent.nseczone.huque.com. does not exist.", out)

    def test_name_cover(self):
        out = run_decode("nsec_nxdomain.wire",
                         "nonexistent.nseczone.huque.com.", "A")
        assert_lines_in_order(self, out, [
            "NSEC: jaguar.nseczone.huque.com. -> sub1.nseczone.huque.com.",
            "Role: Covers the queried name (nonexistent.nseczone.huque.com.)",
        ])

    def test_wildcard_cover(self):
        out = run_decode("nsec_nxdomain.wire",
                         "nonexistent.nseczone.huque.com.", "A")
        assert_lines_in_order(self, out, [
            "NSEC: nseczone.huque.com. -> bar.nseczone.huque.com.",
            "Role: Covers the wildcard (*.nseczone.huque.com.)",
            "no wildcard exists at the closest encloser",
        ])


class TestNSECNxdomainRoot(unittest.TestCase):
    def test_classification(self):
        out = run_decode("nsec_nxdomain_root.wire", "foobar.", "A")
        self.assertIn("NXDOMAIN: foobar. does not exist.", out)
        self.assertIn("Zone: .", out)

    def test_name_and_wildcard_covers(self):
        out = run_decode("nsec_nxdomain_root.wire", "foobar.", "A")
        assert_lines_in_order(self, out, [
            "NSEC: foo. -> food.",
            "Role: Covers the queried name (foobar.)",
            "NSEC: . -> aaa.",
            "Role: Covers the wildcard (*.)",
        ])


class TestNSECCDoE(unittest.TestCase):
    def test_classification(self):
        out = run_decode("nsec_cdoe.wire", "nonexistent.cloudflare.com.", "A")
        self.assertIn(
            "NODATA: nonexistent.cloudflare.com. exists but has no A record.", out)

    def test_cdoe_pattern(self):
        out = run_decode("nsec_cdoe.wire", "nonexistent.cloudflare.com.", "A")
        assert_lines_in_order(self, out, [
            "Compact Denial of Existence (RFC 9824)",
            "NXNAME (TYPE128) present",
        ])

    def test_nsec_next_is_cdoe(self):
        out = run_decode("nsec_cdoe.wire", "nonexistent.cloudflare.com.", "A")
        self.assertIn("\\000.nonexistent.cloudflare.com.", out)


class TestNSEC3Nodata(unittest.TestCase):
    def test_classification(self):
        out = run_decode("nsec3_nodata.wire", "dnskensa.com.", "AAAA")
        self.assertIn("NODATA: dnskensa.com. exists but has no AAAA record.", out)

    def test_hash_and_match(self):
        out = run_decode("nsec3_nodata.wire", "dnskensa.com.", "AAAA")
        assert_lines_in_order(self, out, [
            "H(dnskensa.com.) = TR0OUMQBSM3IL2GRLNPJIJ1V7Q4VFBLL",
            "NSEC3: TR0OUMQBSM3IL2GRLNPJIJ1V7Q4VFBLL ->",
            "Role: Matches H(dnskensa.com.)",
            "does not include AAAA",
        ])

    def test_params(self):
        out = run_decode("nsec3_nodata.wire", "dnskensa.com.", "AAAA")
        self.assertIn("algorithm 1, iterations 10, salt 73B2182A738FCBC4", out)


class TestNSEC3Nxdomain(unittest.TestCase):
    def test_classification(self):
        out = run_decode("nsec3_nxdomain.wire",
                         "foo.nxd123.salesforce.com.", "A")
        self.assertIn(
            "NXDOMAIN: foo.nxd123.salesforce.com. does not exist.", out)

    def test_closest_encloser_proof(self):
        out = run_decode("nsec3_nxdomain.wire",
                         "foo.nxd123.salesforce.com.", "A")
        assert_lines_in_order(self, out, [
            "Closest encloser: salesforce.com.",
            "Next closer name: nxd123.salesforce.com.",
            "Wildcard at CE:   *.salesforce.com.",
            "H(salesforce.com.) = 49STKNJU01HOVPN0L8N7MMD35E9VD3VD",
            "H(nxd123.salesforce.com.) = JP5FLA1OE214J8NI0E55A3GVP96NGINB",
            "H(*.salesforce.com.) = 09UJ9K6OKDGIKMN908E3ULJRDMKM277V",
        ])

    def test_record_ordering_ce_ncn_wc(self):
        out = run_decode("nsec3_nxdomain.wire",
                         "foo.nxd123.salesforce.com.", "A")
        assert_lines_in_order(self, out, [
            "Role: Matches H(salesforce.com.) — closest encloser proof",
            "Role: Covers H(nxd123.salesforce.com.) — next closer name cover",
            "Role: Covers H(*.salesforce.com.) — wildcard cover",
        ])

    def test_wildcard_cover_explanation(self):
        out = run_decode("nsec3_nxdomain.wire",
                         "foo.nxd123.salesforce.com.", "A")
        self.assertIn(
            "no wildcard exists at the closest encloser (salesforce.com.)", out)


class TestNSEC3Wildcard(unittest.TestCase):
    def test_classification(self):
        out = run_decode("nsec3_wildcard.wire",
                         "foo.bar.wild.dnskensa.com.", "A")
        self.assertIn(
            "Wildcard-synthesized answer for foo.bar.wild.dnskensa.com.", out)

    def test_answer_after_classification(self):
        out = run_decode("nsec3_wildcard.wire",
                         "foo.bar.wild.dnskensa.com.", "A")
        assert_lines_in_order(self, out, [
            "Wildcard-synthesized answer",
            "Answer section:",
            "foo.bar.wild.dnskensa.com.",
            "A 10.1.1.1",
        ])

    def test_ncn_cover(self):
        out = run_decode("nsec3_wildcard.wire",
                         "foo.bar.wild.dnskensa.com.", "A")
        assert_lines_in_order(self, out, [
            "Closest encloser: wild.dnskensa.com.",
            "Next closer name: bar.wild.dnskensa.com.",
            "Wildcard:         *.wild.dnskensa.com.",
            "Role: Covers H(bar.wild.dnskensa.com.) — next closer name cover",
            "synthesized from a wildcard",
        ])


class TestNSEC3WildcardNodata(unittest.TestCase):
    def test_classification(self):
        out = run_decode("nsec3_wildcard_nodata.wire",
                         "foo.bar.wild.dnskensa.com.", "AAAA")
        self.assertIn(
            "Wildcard NODATA: foo.bar.wild.dnskensa.com. does not exist", out)
        self.assertIn("*.wild.dnskensa.com. matched", out)

    def test_three_roles(self):
        out = run_decode("nsec3_wildcard_nodata.wire",
                         "foo.bar.wild.dnskensa.com.", "AAAA")
        assert_lines_in_order(self, out, [
            "Role: Covers H(bar.wild.dnskensa.com.) — next closer name cover",
            "Role: Matches H(wild.dnskensa.com.) — closest encloser proof",
            "Role: Matches H(*.wild.dnskensa.com.) — wildcard match",
        ])

    def test_type_absent(self):
        out = run_decode("nsec3_wildcard_nodata.wire",
                         "foo.bar.wild.dnskensa.com.", "AAAA")
        self.assertIn("does not include AAAA, proving the wildcard", out)


class TestCNAMENodata(unittest.TestCase):
    def test_classification(self):
        out = run_decode("cname_nodata.wire", "www.huque.com.", "TLSA")
        self.assertIn("CNAME NODATA: www.huque.com. is an alias", out)
        self.assertIn("cheetara.huque.com. has no TLSA record", out)

    def test_answer_after_classification(self):
        out = run_decode("cname_nodata.wire", "www.huque.com.", "TLSA")
        assert_lines_in_order(self, out, [
            "CNAME NODATA:",
            "Answer section:",
            "CNAME cheetara.huque.com.",
        ])

    def test_cname_in_answer(self):
        out = run_decode("cname_nodata.wire", "www.huque.com.", "TLSA")
        assert_lines_in_order(self, out, [
            "CNAME NODATA:",
            "Answer section:",
            "CNAME cheetara.huque.com.",
        ])

    def test_target_nodata_proof(self):
        out = run_decode("cname_nodata.wire", "www.huque.com.", "TLSA")
        assert_lines_in_order(self, out, [
            "NODATA proof (zone: huque.com.)",
            "H(cheetara.huque.com.) = 33Q996NVAUKA6LERAAPRR2TTBPO5G2MG",
            "Role: Matches H(cheetara.huque.com.) — the CNAME target",
            "does not include TLSA",
        ])


class TestWildcardCNAMENodata(unittest.TestCase):
    def test_classification(self):
        out = run_decode("wildcard_cname_nodata.wire",
                         "12345asdfasfadf.horoscope-divination.com.", "AFSDB")
        self.assertIn("Wildcard CNAME NODATA", out)
        self.assertIn("*.horoscope-divination.com.", out)

    def test_answer_after_classification(self):
        out = run_decode("wildcard_cname_nodata.wire",
                         "12345asdfasfadf.horoscope-divination.com.", "AFSDB")
        assert_lines_in_order(self, out, [
            "Wildcard CNAME NODATA:",
            "Answer section:",
            "CNAME general-beetle-fec22eecz21z3tnuxbx8mde3.herokudns.com.",
        ])

    def test_wildcard_proof(self):
        out = run_decode("wildcard_cname_nodata.wire",
                         "12345asdfasfadf.horoscope-divination.com.", "AFSDB")
        assert_lines_in_order(self, out, [
            "Wildcard proof (zone: horoscope-divination.com.)",
            "next closer name cover (wrap-around)",
            "synthesized from *.horoscope-divination.com.",
        ])

    def test_target_nodata_proof(self):
        out = run_decode("wildcard_cname_nodata.wire",
                         "12345asdfasfadf.horoscope-divination.com.", "AFSDB")
        assert_lines_in_order(self, out, [
            "NODATA proof (zone: herokudns.com.)",
            "Matches the CNAME target",
            "does not include AFSDB",
        ])

    def test_cross_zone(self):
        out = run_decode("wildcard_cname_nodata.wire",
                         "12345asdfasfadf.horoscope-divination.com.", "AFSDB")
        self.assertIn("horoscope-divination.com.)", out)
        self.assertIn("herokudns.com.)", out)


class TestNSEC3NxdomainCircular(unittest.TestCase):
    def test_classification(self):
        out = run_decode("nsec3_nxdomain_circular.wire",
                         "foo.kalebet1363.com.", "AAAA")
        self.assertIn("NXDOMAIN: foo.kalebet1363.com. does not exist.", out)

    def test_single_loop_note(self):
        out = run_decode("nsec3_nxdomain_circular.wire",
                         "foo.kalebet1363.com.", "AAAA")
        self.assertIn(
            "Single NSEC3 record whose owner hash equals its next hash", out)
        self.assertIn("covers the entire hash space", out)

    def test_triple_role(self):
        out = run_decode("nsec3_nxdomain_circular.wire",
                         "foo.kalebet1363.com.", "AAAA")
        assert_lines_in_order(self, out, [
            "Role: Matches H(kalebet1363.com.) — closest encloser proof",
            "Role: Covers H(foo.kalebet1363.com.) — next closer name cover",
            "Role: Covers H(*.kalebet1363.com.) — wildcard cover",
        ])

    def test_all_wrap_around(self):
        out = run_decode("nsec3_nxdomain_circular.wire",
                         "foo.kalebet1363.com.", "AAAA")
        self.assertEqual(out.count("wrap-around"), 2)


class TestDanglingCNAME(unittest.TestCase):
    def test_classification(self):
        out = run_decode("dangling_cname.wire",
                         "danglingcname.dnskensa.com.", "A")
        self.assertIn("CNAME NXDOMAIN", out)
        self.assertIn("danglingcname.dnskensa.com. is an alias for "
                      "nonexistent.dnskensa.com.", out)
        self.assertIn("CNAME target does not exist", out)

    def test_answer_section(self):
        out = run_decode("dangling_cname.wire",
                         "danglingcname.dnskensa.com.", "A")
        assert_lines_in_order(self, out, [
            "CNAME NXDOMAIN:",
            "Answer section:",
            "CNAME nonexistent.dnskensa.com.",
        ])

    def test_nxdomain_proof_uses_target(self):
        out = run_decode("dangling_cname.wire",
                         "danglingcname.dnskensa.com.", "A")
        assert_lines_in_order(self, out, [
            "NXDOMAIN proof (zone: dnskensa.com.)",
            "Closest encloser: dnskensa.com.",
            "Next closer name: nonexistent.dnskensa.com.",
            "H(nonexistent.dnskensa.com.)",
        ])

    def test_not_qname_nxdomain(self):
        out = run_decode("dangling_cname.wire",
                         "danglingcname.dnskensa.com.", "A")
        self.assertNotIn("danglingcname.dnskensa.com. does not exist", out)


class TestDanglingCNAMECrossZone(unittest.TestCase):
    def test_classification(self):
        out = run_decode("dangling_cname_cross_zone.wire",
                         "danglingout.dnskensa.com.", "A")
        self.assertIn("CNAME NXDOMAIN", out)
        self.assertIn("danglingout.dnskensa.com. is an alias for "
                      "foo.bar.blah.salesforce.com.", out)
        self.assertIn("CNAME target does not exist", out)

    def test_answer_section(self):
        out = run_decode("dangling_cname_cross_zone.wire",
                         "danglingout.dnskensa.com.", "A")
        assert_lines_in_order(self, out, [
            "CNAME NXDOMAIN:",
            "Answer section:",
            "CNAME foo.bar.blah.salesforce.com.",
        ])

    def test_nxdomain_proof_in_target_zone(self):
        out = run_decode("dangling_cname_cross_zone.wire",
                         "danglingout.dnskensa.com.", "A")
        assert_lines_in_order(self, out, [
            "NXDOMAIN proof (zone: salesforce.com.)",
            "Closest encloser: salesforce.com.",
            "Next closer name: blah.salesforce.com.",
            "H(blah.salesforce.com.)",
        ])

    def test_not_qname_nxdomain(self):
        out = run_decode("dangling_cname_cross_zone.wire",
                         "danglingout.dnskensa.com.", "A")
        self.assertNotIn("danglingout.dnskensa.com. does not exist", out)


if __name__ == "__main__":
    unittest.main()
