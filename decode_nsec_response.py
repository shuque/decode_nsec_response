#!/usr/bin/env python3

"""
Decode and explain NSEC/NSEC3 records in DNS responses.

Queries a given qname/qtype and explains the authenticated denial of
existence records in the authority section: which names are covered or
matched, the role of each record in the proof, type bitmap analysis,
wrap-around detection, and NSEC3 hash computations.

By default, uses the local system resolver. Use --doh to query via
DNS-over-HTTPS to Cloudflare (or a custom server with --doh-server).
"""

import sys
import base64
import argparse
from collections import namedtuple

import dns.name
import dns.query
import dns.message
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.flags
import dns.dnssec

__version__ = '0.0.1'

DEFAULT_DOH_URL = "https://cloudflare-dns.com/dns-query"

NXNAME_TYPE = 128

CEProof = namedtuple('CEProof', ['ce_name', 'ce_rec', 'ncn_name', 'ncn_hash',
                                 'ncn_rec', 'wc_name', 'wc_hash', 'wc_rec'])


def query_dns(qname, rdtype, doh_url=None, resolver_ip=None):
    """Send a DNS query and return the response."""
    q = dns.message.make_query(qname, rdtype, want_dnssec=True)
    q.flags |= dns.flags.AD
    if doh_url:
        return dns.query.https(q, doh_url)
    nameserver = resolver_ip or dns.resolver.Resolver().nameservers[0]
    return dns.query.udp(q, nameserver)


def get_bitmap_types(rdata):
    """Extract the set of RR type numbers from an NSEC/NSEC3 bitmap."""
    types = set()
    for window, bitmap in rdata.windows:
        for i, byte_val in enumerate(bitmap):
            for bit in range(8):
                if byte_val & (0x80 >> bit):
                    types.add(window * 256 + i * 8 + bit)
    return types


def format_types(types):
    """Format a set of RR type numbers as a readable string."""
    if not types:
        return "(empty)"
    parts = []
    for t in sorted(types):
        try:
            parts.append(dns.rdatatype.to_text(t))
        except Exception:
            parts.append(f"TYPE{t}")
    return ' '.join(parts)


_B32_TO_B32HEX = str.maketrans(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
    '0123456789ABCDEFGHIJKLMNOPQRSTUV',
)


def bytes_to_b32hex(data):
    """Encode raw bytes as base32hex (no padding), uppercase."""
    if hasattr(base64, 'b32hexencode'):
        return base64.b32hexencode(data).decode().rstrip('=')
    return base64.b32encode(data).decode().translate(_B32_TO_B32HEX).rstrip('=')


def nsec3_hash_name(name, salt_hex, iterations):
    """Compute the NSEC3 hash of a DNS name."""
    if salt_hex == '-' or salt_hex == '':
        salt = b''
    else:
        salt = bytes.fromhex(salt_hex)
    return dns.dnssec.nsec3_hash(name, salt, iterations, 'SHA1')


def nsec_covers(owner, nxt, target, origin):
    """Check if an NSEC range (owner, nxt) covers target.
    Returns (covers, is_wraparound)."""
    o = owner.relativize(origin).canonicalize()
    n = nxt.relativize(origin).canonicalize()
    t = target.relativize(origin).canonicalize()
    if o < n:
        return o < t < n, False
    else:
        return t > o or t < n, True


def nsec3_covers(owner_hash, next_hash, target_hash):
    """Check if an NSEC3 range covers target_hash.
    Returns (covers, is_wraparound)."""
    o = owner_hash.upper()
    n = next_hash.upper()
    t = target_hash.upper()
    if o < n:
        return o < t < n, False
    else:
        return t > o or t < n, True


def find_zone_from_soa(response):
    """Extract zone name from SOA in authority section."""
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.SOA:
            return rrset.name
    return None


def find_zone_from_rrsig(response):
    """Infer zone from RRSIG signer name in authority section."""
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.RRSIG:
            for rdata in rrset:
                return rdata.signer
    return None


def find_closest_encloser_nsec(qname, zone):
    """Walk up from qname to find the closest encloser within the zone.
    For NSEC, we return candidate closest enclosers to check against."""
    candidates = []
    name = qname
    while name != zone and name.is_subdomain(zone):
        candidates.append(name)
        name = name.parent()
    candidates.append(zone)
    return candidates


def get_nsec_records(response):
    """Extract NSEC records from authority section.
    Returns list of (owner_name, next_name, types, rdata)."""
    records = []
    for rrset in response.authority:
        if rrset.rdtype != dns.rdatatype.NSEC:
            continue
        for rdata in rrset:
            types = get_bitmap_types(rdata)
            records.append((rrset.name, rdata.next, types, rdata))
    return records


def get_nsec3_records(response):
    """Extract NSEC3 records from authority section.
    Returns list of (owner_name, owner_hash, next_hash, types, rdata)."""
    records = []
    for rrset in response.authority:
        if rrset.rdtype != dns.rdatatype.NSEC3:
            continue
        owner_hash = rrset.name.labels[0].decode().upper()
        for rdata in rrset:
            next_hash = bytes_to_b32hex(rdata.next)
            types = get_bitmap_types(rdata)
            records.append((rrset.name, owner_hash, next_hash, types, rdata))
    return records


def get_nsec3_params(rdata):
    """Extract NSEC3 parameters from an NSEC3 rdata."""
    salt_hex = rdata.salt.hex().upper() if rdata.salt else '-'
    return rdata.algorithm, rdata.flags, rdata.iterations, salt_hex


def print_nsec3_params(nsec3_records):
    """Print NSEC3 parameters and return (salt_hex, iterations)."""
    params = get_nsec3_params(nsec3_records[0][4])
    algo, _, iterations, salt_hex = params
    salt_display = salt_hex if salt_hex != '-' else '(empty)'
    print(f"NSEC3 params: algorithm {algo}, iterations {iterations}, "
          f"salt {salt_display}")
    return salt_hex, iterations


def print_nsec3_record(owner_hash, next_hash, types, rdata):
    """Print an NSEC3 record's hash range and type bitmap."""
    opt_out = " [OPT-OUT]" if rdata.flags & 0x01 else ""
    print(f"\n  NSEC3: {owner_hash} -> {next_hash}{opt_out}")
    print(f"    Type bitmap: [{format_types(types)}]")


def print_nsec3_optout(rdata):
    """Print opt-out notice if the NSEC3 flag is set."""
    if rdata.flags & 0x01:
        print(f"    Opt-out flag set: unsigned delegations may "
              f"exist within this range.")


def find_nsec3_ce_proof(qname, nsec3_records, zone, salt_hex, iterations,
                        wc_mode='cover'):
    """Walk from zone apex toward qname to find the NSEC3 closest encloser proof.

    wc_mode controls how the wildcard at CE is matched:
      'cover' — look for an NSEC3 that covers H(*.CE) (NXDOMAIN)
      'match' — look for an NSEC3 whose owner matches H(*.CE) (wildcard NODATA)

    Returns a CEProof namedtuple or None."""
    candidates = []
    name = qname
    while name.is_subdomain(zone):
        candidates.append(name)
        name = name.parent()

    for candidate in reversed(candidates):
        h_candidate = nsec3_hash_name(candidate, salt_hex, iterations)
        for owner_name, owner_hash, next_hash, types, rdata in nsec3_records:
            if owner_hash != h_candidate:
                continue

            ce_rec = (owner_name, owner_hash, next_hash, types, rdata)
            idx = candidates.index(candidate) - 1
            if idx < 0:
                return CEProof(candidate, ce_rec, None, None, None,
                               None, None, None)

            rel = qname.relativize(candidate)
            ncn_name = dns.name.Name((rel.labels[-1],) + candidate.labels)
            h_ncn = nsec3_hash_name(ncn_name, salt_hex, iterations)
            wc_name = dns.name.Name((b'*',) + candidate.labels)
            h_wc = nsec3_hash_name(wc_name, salt_hex, iterations)

            ncn_rec = None
            wc_rec = None
            for on, oh, nh, ty, rd in nsec3_records:
                if ncn_rec is None:
                    covers, _ = nsec3_covers(oh, nh, h_ncn)
                    if covers:
                        ncn_rec = (on, oh, nh, ty, rd)
                if wc_rec is None:
                    if wc_mode == 'cover':
                        covers_wc, _ = nsec3_covers(oh, nh, h_wc)
                        if covers_wc:
                            wc_rec = (on, oh, nh, ty, rd)
                    elif wc_mode == 'match' and oh == h_wc:
                        wc_rec = (on, oh, nh, ty, rd)

            return CEProof(candidate, ce_rec, ncn_name, h_ncn, ncn_rec,
                           wc_name, h_wc, wc_rec)

    return None


def explain_nsec_cdoe(qname, nxt, types):
    """Detect and explain NSEC Compact Denial of Existence (RFC 9824)."""
    cdoe_next = dns.name.Name((b'\x00',) + qname.labels)
    if nxt != cdoe_next:
        return
    nxname = NXNAME_TYPE in types
    real_types = types - {dns.rdatatype.RRSIG, dns.rdatatype.NSEC, NXNAME_TYPE}
    if nxname:
        print(f"\n    Pattern: Compact Denial of Existence (RFC 9824)")
        print(f"    Next name = \\000.{qname} (CDoE signature)")
        print(f"    NXNAME (TYPE128) present — name does not exist")
    elif not real_types:
        print(f"\n    Pattern: Compact Denial of Existence (RFC 9824)")
        print(f"    Next name = \\000.{qname} (CDoE signature)")
        print(f"    Bitmap has no real types — likely CDoE without NXNAME")
    else:
        print(f"\n    Next name = \\000.{qname}")
        print(f"    This name has children in the zone; the \\000 child "
              f"label ensures the NSEC")
        print(f"    range does not cover existing child names.")


def explain_nsec3_cdoe(types):
    """Detect and explain NSEC3 Compact Denial of Existence (RFC 9824 Section 4)."""
    cdoe_types = types - {dns.rdatatype.RRSIG, dns.rdatatype.NSEC3}
    has_nxname = NXNAME_TYPE in cdoe_types
    is_minimal = cdoe_types <= {NXNAME_TYPE}
    if not is_minimal:
        return
    print(f"\n    Pattern: Compact Denial of Existence with NSEC3 "
          f"(RFC 9824 Section 4)")
    if has_nxname:
        print(f"    NXNAME (TYPE128) present — name does not exist")
    else:
        print(f"    Minimal bitmap (no real types) — likely CDoE "
              f"without NXNAME")


def has_answer_data(response):
    """Check if the response has non-RRSIG answer records."""
    return any(
        rrset.rdtype != dns.rdatatype.RRSIG
        for rrset in response.answer
    )


def get_cname_chain(response, qname):
    """Follow the CNAME chain in the answer section.
    Returns (chain, final_target) where chain is a list of (name, target)
    pairs and final_target is the last target. Returns ([], None) if no CNAME."""
    cnames = {}
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.CNAME:
            for rdata in rrset:
                cnames[rrset.name] = rdata.target
    if not cnames or qname not in cnames:
        return [], None
    chain = []
    current = qname
    seen = set()
    while current in cnames and current not in seen:
        seen.add(current)
        target = cnames[current]
        chain.append((current, target))
        current = target
    return chain, current


def get_wildcard_from_rrsig(response, owner, rdtype):
    """Check if an RRset was wildcard-synthesized by examining RRSIG labels.
    Returns the wildcard name if synthesized, None otherwise."""
    owner_label_count = len(owner) - 1
    for rrset in response.answer:
        if rrset.name != owner or rrset.rdtype != dns.rdatatype.RRSIG:
            continue
        for rdata in rrset:
            if rdata.type_covered == rdtype and rdata.labels < owner_label_count:
                ce = dns.name.Name(owner.labels[-(rdata.labels + 1):])
                return dns.name.Name((b'*',) + ce.labels)
    return None


def has_non_cname_answer(response):
    """Check if the answer section has data beyond CNAME/RRSIG records."""
    return any(
        rrset.rdtype not in (dns.rdatatype.CNAME, dns.rdatatype.RRSIG)
        for rrset in response.answer
    )


def is_referral(response):
    """Check if the response is a referral (NS in authority, no answer)."""
    if response.rcode() != dns.rcode.NOERROR:
        return False
    if has_answer_data(response):
        return False
    return any(
        rrset.rdtype == dns.rdatatype.NS
        for rrset in response.authority
    )


def print_header(qname, qtype_str, rcode, response):
    """Print the response header."""
    flags = []
    if response.flags & dns.flags.AA:
        flags.append("AA")
    if response.flags & dns.flags.AD:
        flags.append("AD")
    flags_str = f" [{', '.join(flags)}]" if flags else ""

    print(f"\nQuery: {qname} {qtype_str}")
    print(f"Response: {dns.rcode.to_text(rcode)}{flags_str}")
    print(f"{'=' * 70}")


def explain_nsec_nodata(qname, qtype, nsec_records, zone):
    """Explain NSEC records in a NODATA response."""
    qtype_num = dns.rdatatype.from_text(qtype) if isinstance(qtype, str) else qtype

    is_wildcard_nodata = False
    for owner, nxt, types, rdata in nsec_records:
        if owner == qname:
            break
        if str(owner.labels[0], errors='replace') == '*':
            wc_parent = dns.name.Name(owner.labels[1:])
            if qname.is_subdomain(wc_parent):
                is_wildcard_nodata = True
                break
        if zone:
            covers, _ = nsec_covers(owner, nxt, qname, zone)
            if covers:
                is_wildcard_nodata = True
                break

    if is_wildcard_nodata:
        print(f"\nWildcard NODATA: {qname} does not exist, but a wildcard "
              f"matched.")
        print(f"The wildcard lacks a {qtype} record.")
    else:
        print(f"\nNODATA: {qname} exists but has no {qtype} record.")
    print(f"\nAuthority section:")

    for owner, nxt, types, rdata in nsec_records:
        print(f"\n  NSEC: {owner} -> {nxt}")
        print(f"    Type bitmap: [{format_types(types)}]")

        if owner == qname:
            print(f"\n    Role: Matches the queried name ({qname})")

            if qtype_num in types:
                print(f"    NOTE: {qtype} IS present in the bitmap — "
                      f"unexpected for NODATA")
            else:
                print(f"    The type bitmap does not include {qtype}, "
                      f"proving no {qtype} record exists at this name.")

            explain_nsec_cdoe(qname, nxt, types)
        else:
            if str(owner.labels[0], errors='replace') == '*':
                wc_parent = dns.name.Name(owner.labels[1:])
                if qname.is_subdomain(wc_parent):
                    print(f"\n    Role: Wildcard NSEC at {owner}")
                    print(f"    The wildcard matched {qname} but its "
                          f"type bitmap does not include {qtype},")
                    print(f"    proving no {qtype} data can be "
                          f"synthesized.")
                    continue

            covers, wraparound = nsec_covers(owner, nxt, qname, zone) \
                if zone else (False, False)
            if covers:
                wrap_note = " (wrap-around)" if wraparound else ""
                print(f"\n    Role: Covers the queried name "
                      f"({qname}){wrap_note}")
                print(f"    Proves {qname} does not exist as an exact "
                      f"name.")
                print(f"    The response is NODATA because a wildcard "
                      f"matched,")
                print(f"    but the wildcard lacks a {qtype} record.")
            elif qname.is_subdomain(owner):
                print(f"\n    Owner ({owner}) does not match qname "
                      f"({qname}).")
                print(f"    However, qname is a subdomain of the owner.")
            else:
                print(f"\n    Owner ({owner}) does not match qname "
                      f"({qname}).")


def explain_nsec_nxdomain(qname, nsec_records, zone):
    """Explain NSEC records in an NXDOMAIN response."""
    candidates = find_closest_encloser_nsec(qname, zone)

    name_cover = None
    wildcard_cover = None

    for owner, nxt, types, rdata in nsec_records:
        covers, wraparound = nsec_covers(owner, nxt, qname, zone)
        if covers:
            name_cover = (owner, nxt, types, wraparound)

        for ce in candidates[1:]:
            wc_name = dns.name.Name((b'*',) + ce.labels)
            wc_covers, wc_wrap = nsec_covers(owner, nxt, wc_name, zone)
            if wc_covers:
                wildcard_cover = (owner, nxt, types, wc_wrap, ce, wc_name)
                break

    for owner, nxt, types, rdata in nsec_records:
        print(f"\n  NSEC: {owner} -> {nxt}")
        print(f"    Type bitmap: [{format_types(types)}]")

        if name_cover and owner == name_cover[0] and nxt == name_cover[1]:
            wrap_note = " (wrap-around: last NSEC in chain)" \
                if name_cover[3] else ""
            print(f"\n    Role: Covers the queried name ({qname}){wrap_note}")
            print(f"    Owner sorts before qname, next sorts after qname")
            print(f"    in canonical order, proving {qname} does not exist.")

        if wildcard_cover and owner == wildcard_cover[0] \
                and nxt == wildcard_cover[1]:
            ce = wildcard_cover[4]
            wc_name = wildcard_cover[5]
            wrap_note = " (wrap-around)" if wildcard_cover[3] else ""
            print(f"\n    Role: Covers the wildcard ({wc_name}){wrap_note}")
            print(f"    Proves no wildcard exists at the closest encloser "
                  f"({ce}),")
            print(f"    so no wildcard synthesis can produce an answer.")

    if not name_cover:
        print(f"\n  WARNING: No NSEC found that covers qname ({qname})")
    if not wildcard_cover:
        print(f"\n  WARNING: No NSEC found that covers a wildcard "
              f"at any ancestor")


def explain_nsec_wildcard(qname, nsec_records, zone):
    """Explain NSEC records in a wildcard-synthesized response."""
    for owner, nxt, types, rdata in nsec_records:
        print(f"\n  NSEC: {owner} -> {nxt}")
        print(f"    Type bitmap: [{format_types(types)}]")

        covers, wraparound = nsec_covers(owner, nxt, qname, zone)
        if covers:
            wrap_note = " (wrap-around)" if wraparound else ""
            print(f"\n    Role: Covers the queried name "
                  f"({qname}){wrap_note}")
            print(f"    Proves no exact match exists for {qname},")
            print(f"    validating that the answer was synthesized "
                  f"from a wildcard.")
        else:
            print(f"\n    Role: Does not cover the queried name.")


def explain_nsec_referral(qname, nsec_records, zone):
    """Explain NSEC records in a referral (unsigned delegation)."""
    for owner, nxt, types, rdata in nsec_records:
        print(f"\n  NSEC: {owner} -> {nxt}")
        print(f"    Type bitmap: [{format_types(types)}]")

        if owner == qname or owner == dns.name.from_text(
                qname.to_text()):
            if dns.rdatatype.DS not in types:
                print(f"\n    Role: Matches the delegation point ({owner})")
                print(f"    DS is absent from the type bitmap, proving")
                print(f"    this is an unsigned delegation (no DS record).")
            if dns.rdatatype.NS in types:
                print(f"    NS is present, confirming this is a "
                      f"delegation point.")
        else:
            delegation_name = None
            name = qname
            while name != zone and name.is_subdomain(zone):
                if owner == name:
                    delegation_name = name
                    break
                name = name.parent()

            if delegation_name:
                if dns.rdatatype.DS not in types:
                    print(f"\n    Role: Matches the delegation point "
                          f"({delegation_name})")
                    print(f"    DS is absent from the type bitmap, "
                          f"proving unsigned delegation.")
            else:
                covers, wraparound = nsec_covers(owner, nxt, qname, zone)
                if covers:
                    wrap_note = " (wrap-around)" if wraparound else ""
                    print(f"\n    Role: Covers the queried name "
                          f"({qname}){wrap_note}")
                    print(f"    Proves no DS record exists at this point "
                          f"in the zone.")


def explain_nsec3_nodata(qname, qtype_str, nsec3_records, zone,
                        salt_hex, iterations):
    """Explain NSEC3 records in a NODATA response."""
    qtype_num = dns.rdatatype.from_text(qtype_str) \
        if isinstance(qtype_str, str) else qtype_str
    h_qname = nsec3_hash_name(qname, salt_hex, iterations)
    print(f"\n  H({qname}) = {h_qname}")

    exact_match = any(oh == h_qname
                      for _, oh, _, _, _ in nsec3_records)

    if exact_match:
        print(f"\nNODATA: {qname} exists but has no {qtype_str} record.")
        print(f"\nAuthority section:")
        for owner_name, owner_hash, next_hash, types, rdata in nsec3_records:
            print_nsec3_record(owner_hash, next_hash, types, rdata)

            if owner_hash == h_qname:
                print(f"\n    Role: Matches H({qname})")

                if isinstance(qtype_str, str):
                    if qtype_num in types:
                        print(f"    NOTE: {qtype_str} IS present in the "
                              f"bitmap — unexpected for NODATA")
                    else:
                        print(f"    The type bitmap does not include "
                              f"{qtype_str}, proving no {qtype_str} "
                              f"record exists at this name.")

                explain_nsec3_cdoe(types)

            print_nsec3_optout(rdata)
        return

    _explain_nsec3_wildcard_nodata(
        qname, qtype_str, qtype_num, nsec3_records, zone,
        salt_hex, iterations, h_qname)


def _explain_nsec3_wildcard_nodata(qname, qtype_str, qtype_num,
                                   nsec3_records, zone, salt_hex,
                                   iterations, h_qname):
    """Explain NSEC3 wildcard NODATA: qname doesn't exist, a wildcard
    matched, but the wildcard lacks the queried type."""
    proof = find_nsec3_ce_proof(qname, nsec3_records, zone, salt_hex,
                                iterations, wc_mode='match')

    if proof and proof.ce_name:
        print(f"\n  Wildcard NODATA: {qname} does not exist, but "
              f"{proof.wc_name} matched.")
        print(f"  The wildcard lacks a {qtype_str} record.")
        print(f"\n  Closest encloser: {proof.ce_name}")
        print(f"  Next closer name: {proof.ncn_name}")
        print(f"  Wildcard at CE:   {proof.wc_name}")
        if proof.ncn_rec:
            print(f"  H({proof.ncn_name}) = {proof.ncn_hash}")
        print(f"  H({proof.wc_name}) = {proof.wc_hash}")

    print(f"\nAuthority section:")
    for owner_name, owner_hash, next_hash, types, rdata in nsec3_records:
        print_nsec3_record(owner_hash, next_hash, types, rdata)

        if proof and proof.ce_rec and owner_hash == proof.ce_rec[1]:
            print(f"\n    Role: Matches H({proof.ce_name}) — closest "
                  f"encloser proof")
            print(f"    Proves {proof.ce_name} exists in the zone.")

        elif proof and proof.ncn_rec \
                and owner_hash == proof.ncn_rec[1] \
                and next_hash == proof.ncn_rec[2]:
            _, wraparound = nsec3_covers(owner_hash, next_hash,
                                         proof.ncn_hash)
            wrap_note = " (wrap-around)" if wraparound else ""
            print(f"\n    Role: Covers H({proof.ncn_name}) — next closer "
                  f"name cover{wrap_note}")
            print(f"    Proves {proof.ncn_name} does not exist, so the "
                  f"wildcard applies.")

        elif proof and proof.wc_rec and owner_hash == proof.wc_rec[1]:
            print(f"\n    Role: Matches H({proof.wc_name}) — wildcard "
                  f"match")
            if isinstance(qtype_str, str):
                if qtype_num in types:
                    print(f"    NOTE: {qtype_str} IS present in the "
                          f"bitmap — unexpected for wildcard NODATA")
                else:
                    print(f"    The type bitmap does not include "
                          f"{qtype_str}, proving the wildcard")
                    print(f"    cannot synthesize a {qtype_str} record.")

        else:
            covers, wraparound = nsec3_covers(
                owner_hash, next_hash, h_qname)
            if covers:
                wrap_note = " (wrap-around)" if wraparound else ""
                print(f"\n    Role: Covers H({qname}){wrap_note}")

        print_nsec3_optout(rdata)


def explain_nsec3_nxdomain(qname, nsec3_records, zone, salt_hex, iterations):
    """Explain NSEC3 records in an NXDOMAIN response."""
    h_qname = nsec3_hash_name(qname, salt_hex, iterations)
    proof = find_nsec3_ce_proof(qname, nsec3_records, zone, salt_hex,
                                iterations, wc_mode='cover')

    if proof and proof.ce_name:
        h_ce = nsec3_hash_name(proof.ce_name, salt_hex, iterations)
        print(f"\n  Closest encloser: {proof.ce_name}")
        print(f"  Next closer name: {proof.ncn_name}")
        print(f"  Wildcard at CE:   {proof.wc_name}")
        print(f"  H({proof.ce_name}) = {h_ce}")
        print(f"  H({proof.ncn_name}) = {proof.ncn_hash}")
        print(f"  H({proof.wc_name}) = {proof.wc_hash}")

    if proof and proof.ce_rec:
        ordered = []
        remaining = []
        for rec in nsec3_records:
            owner_name, owner_hash, next_hash, types, rdata = rec
            if owner_hash == proof.ce_rec[1]:
                ordered.insert(0, rec)
            elif proof.ncn_rec and owner_hash == proof.ncn_rec[1] \
                    and next_hash == proof.ncn_rec[2]:
                ordered.insert(1 if len(ordered) >= 1 else 0, rec)
            elif proof.wc_rec and owner_hash == proof.wc_rec[1] \
                    and next_hash == proof.wc_rec[2]:
                ordered.append(rec)
            else:
                remaining.append(rec)
        ordered.extend(remaining)

        single_loop = (len(nsec3_records) == 1
                       and nsec3_records[0][1] == nsec3_records[0][2])
        if single_loop:
            print(f"\n  Note: Single NSEC3 record whose owner hash equals "
                  f"its next hash.")
            print(f"  This covers the entire hash space, proving no "
                  f"other names exist in the zone.")

        for owner_name, owner_hash, next_hash, types, rdata in ordered:
            print_nsec3_record(owner_hash, next_hash, types, rdata)

            matched = False
            if owner_hash == proof.ce_rec[1]:
                matched = True
                print(f"\n    Role: Matches H({proof.ce_name}) — closest "
                      f"encloser proof")
                print(f"    Proves {proof.ce_name} exists in the zone.")

            if proof.ncn_rec and owner_hash == proof.ncn_rec[1] \
                    and next_hash == proof.ncn_rec[2]:
                matched = True
                _, wraparound = nsec3_covers(
                    owner_hash, next_hash, proof.ncn_hash)
                wrap_note = " (wrap-around)" if wraparound else ""
                print(f"\n    Role: Covers H({proof.ncn_name}) — next "
                      f"closer name cover{wrap_note}")
                print(f"    Proves {proof.ncn_name} does not exist.")

            if proof.wc_rec and owner_hash == proof.wc_rec[1] \
                    and next_hash == proof.wc_rec[2]:
                matched = True
                _, wraparound = nsec3_covers(
                    owner_hash, next_hash, proof.wc_hash)
                wrap_note = " (wrap-around)" if wraparound else ""
                print(f"\n    Role: Covers H({proof.wc_name}) — wildcard "
                      f"cover{wrap_note}")
                print(f"    Proves no wildcard exists at the closest "
                      f"encloser ({proof.ce_name}),")
                print(f"    so no wildcard synthesis can produce an "
                      f"answer.")

            if not matched:
                covers, wraparound = nsec3_covers(
                    owner_hash, next_hash, h_qname)
                if covers:
                    wrap_note = " (wrap-around)" if wraparound else ""
                    print(f"\n    Role: Covers H({qname}){wrap_note}")

            print_nsec3_optout(rdata)

    if not proof or not proof.ce_rec:
        print(f"\n  NOTE: Could not identify closest encloser match.")
        print(f"  Showing raw NSEC3 coverage analysis:")
        for owner_name, owner_hash, next_hash, types, rdata in nsec3_records:
            covers, wraparound = nsec3_covers(
                owner_hash, next_hash, h_qname)
            if covers:
                wrap_note = " (wrap-around)" if wraparound else ""
                print(f"    {owner_hash} -> {next_hash} covers "
                      f"H({qname}){wrap_note}")


def explain_nsec3_wildcard(qname, nsec3_records, zone, salt_hex, iterations):
    """Explain NSEC3 records in a wildcard-synthesized response."""
    candidates = []
    name = qname.parent()
    while name.is_subdomain(zone):
        candidates.append(name)
        name = name.parent()

    ncn_match = None
    for owner_name, owner_hash, next_hash, types, rdata in nsec3_records:
        for ce in candidates:
            rel = qname.relativize(ce)
            ncn = dns.name.Name((rel.labels[-1],) + ce.labels)
            h_ncn = nsec3_hash_name(ncn, salt_hex, iterations)
            cov, wrap = nsec3_covers(owner_hash, next_hash, h_ncn)
            if cov:
                ncn_match = (owner_hash, next_hash, ncn, h_ncn, ce, wrap)
                break
        if ncn_match:
            break

    if ncn_match:
        ncn_name = ncn_match[2]
        h_ncn = ncn_match[3]
        ce = ncn_match[4]
        wc = dns.name.Name((b'*',) + ce.labels)
        print(f"\n  Closest encloser: {ce}")
        print(f"  Next closer name: {ncn_name}")
        print(f"  Wildcard:         {wc}")
        print(f"  H({ncn_name}) = {h_ncn}")

    for owner_name, owner_hash, next_hash, types, rdata in nsec3_records:
        print_nsec3_record(owner_hash, next_hash, types, rdata)

        if ncn_match and owner_hash == ncn_match[0] \
                and next_hash == ncn_match[1]:
            wrap_note = " (wrap-around)" if ncn_match[5] else ""
            ncn_name = ncn_match[2]
            print(f"\n    Role: Covers H({ncn_name}) — next closer name "
                  f"cover{wrap_note}")
            print(f"    Proves no closer match than {ncn_match[4]} exists "
                  f"for {qname},")
            print(f"    validating that the answer was synthesized "
                  f"from a wildcard.")
        else:
            covers, wraparound = nsec3_covers(
                owner_hash, next_hash,
                nsec3_hash_name(qname, salt_hex, iterations))
            if covers:
                wrap_note = " (wrap-around)" if wraparound else ""
                print(f"\n    Role: Covers H({qname}){wrap_note}")

        print_nsec3_optout(rdata)


def explain_nsec3_referral(qname, nsec3_records, zone, salt_hex, iterations):
    """Explain NSEC3 records in a referral (unsigned delegation)."""
    delegation_name = None
    name = qname
    while name != zone and name.is_subdomain(zone):
        delegation_name = name
        name = name.parent()
    if not delegation_name:
        delegation_name = qname

    h_deleg = nsec3_hash_name(delegation_name, salt_hex, iterations)
    print(f"\n  H({delegation_name}) = {h_deleg}")

    for owner_name, owner_hash, next_hash, types, rdata in nsec3_records:
        print_nsec3_record(owner_hash, next_hash, types, rdata)

        if owner_hash == h_deleg:
            if dns.rdatatype.DS not in types:
                print(f"\n    Role: Matches H({delegation_name})")
                print(f"    DS is absent from the type bitmap, proving")
                print(f"    this is an unsigned delegation (no DS record).")
        else:
            covers, wraparound = nsec3_covers(
                owner_hash, next_hash, h_deleg)
            if covers:
                wrap_note = " (wrap-around)" if wraparound else ""
                print(f"\n    Role: Covers H({delegation_name})"
                      f"{wrap_note}")
                print(f"    Proves no DS record exists for this "
                      f"delegation.")

        print_nsec3_optout(rdata)


def get_rrsig_signer(response, owner_name, rdtype):
    """Get the RRSIG signer name for a given RRset in the authority section."""
    for rrset in response.authority:
        if rrset.name == owner_name and rrset.rdtype == dns.rdatatype.RRSIG:
            for rdata in rrset:
                if rdata.type_covered == rdtype:
                    return rdata.signer
    return None


def partition_records_by_zone(nsec_records, nsec3_records, response):
    """Partition NSEC/NSEC3 records by their zone (RRSIG signer).
    Returns dict mapping zone_name -> (nsec_list, nsec3_list)."""
    zones = {}
    for rec in nsec_records:
        owner = rec[0]
        signer = get_rrsig_signer(response, owner, dns.rdatatype.NSEC)
        if signer:
            zones.setdefault(signer, ([], []))
            zones[signer][0].append(rec)
    for rec in nsec3_records:
        owner = rec[0]
        signer = get_rrsig_signer(response, owner, dns.rdatatype.NSEC3)
        if signer:
            zones.setdefault(signer, ([], []))
            zones[signer][1].append(rec)
    return zones


def explain_cname_nodata(qname, qtype_str, cname_chain, target,
                         nsec_records, nsec3_records, response):
    """Explain NSEC/NSEC3 records proving the CNAME target lacks the queried type."""
    cname_src = cname_chain[0][0]
    wildcard = get_wildcard_from_rrsig(response, cname_src,
                                       dns.rdatatype.CNAME)

    if wildcard:
        wc_parent = dns.name.Name(wildcard.labels[1:])
        print(f"\nWildcard CNAME NODATA: {qname} matched wildcard "
              f"{wildcard},")
        print(f"which targets {target}. The target has no {qtype_str} "
              f"record.")
    else:
        print(f"\nCNAME NODATA: {qname} is an alias; the final target "
              f"{target} has no {qtype_str} record.")
    print_answer_section(response)
    print(f"\nAuthority section:")

    zone_records = partition_records_by_zone(nsec_records, nsec3_records,
                                             response)

    if wildcard:
        wc_zone = dns.name.Name(wildcard.labels[1:])
        owner_zone_recs = zone_records.pop(wc_zone, None)
        if owner_zone_recs:
            owner_nsec, owner_nsec3 = owner_zone_recs
            print(f"\n  --- Wildcard proof (zone: {wc_zone}) ---")
            if owner_nsec:
                _explain_nsec_wildcard_cname(
                    qname, wildcard, owner_nsec, wc_zone)
            elif owner_nsec3:
                salt_hex, iterations = print_nsec3_params(owner_nsec3)
                _explain_nsec3_wildcard_cname(
                    qname, wildcard, owner_nsec3, wc_zone,
                    salt_hex, iterations)

    for zone_name, (z_nsec, z_nsec3) in zone_records.items():
        print(f"\n  --- NODATA proof (zone: {zone_name}) ---")
        if z_nsec:
            _explain_nsec_cname_nodata(target, qtype_str, z_nsec,
                                       zone_name)
        if z_nsec3:
            salt_hex, iterations = print_nsec3_params(z_nsec3)
            _explain_nsec3_cname_nodata(target, qtype_str, z_nsec3,
                                        zone_name, salt_hex, iterations)


def _explain_nsec_wildcard_cname(qname, wildcard, nsec_records, zone):
    """Explain NSEC proving the wildcard CNAME was legitimate."""
    for owner, nxt, types, rdata in nsec_records:
        print(f"\n  NSEC: {owner} -> {nxt}")
        print(f"    Type bitmap: [{format_types(types)}]")

        covers, wraparound = nsec_covers(owner, nxt, qname, zone)
        if covers:
            wrap_note = " (wrap-around)" if wraparound else ""
            print(f"\n    Role: Covers the queried name "
                  f"({qname}){wrap_note}")
            print(f"    Proves no exact match exists for {qname},")
            print(f"    validating that the CNAME was synthesized "
                  f"from {wildcard}.")


def _explain_nsec3_wildcard_cname(qname, wildcard, nsec3_records, zone,
                                  salt_hex, iterations):
    """Explain NSEC3 proving the wildcard CNAME was legitimate."""
    wc_parent = dns.name.Name(wildcard.labels[1:])
    rel = qname.relativize(wc_parent)
    ncn = dns.name.Name((rel.labels[-1],) + wc_parent.labels)
    h_ncn = nsec3_hash_name(ncn, salt_hex, iterations)

    print(f"\n  Closest encloser: {wc_parent}")
    print(f"  Next closer name: {ncn}")
    print(f"  Wildcard:         {wildcard}")
    print(f"  H({ncn}) = {h_ncn}")

    for owner_name, owner_hash, next_hash, types, rdata in nsec3_records:
        print_nsec3_record(owner_hash, next_hash, types, rdata)

        covers, wraparound = nsec3_covers(owner_hash, next_hash, h_ncn)
        if covers:
            wrap_note = " (wrap-around)" if wraparound else ""
            print(f"\n    Role: Covers H({ncn}) — next closer name "
                  f"cover{wrap_note}")
            print(f"    Proves no closer match than {wc_parent} exists "
                  f"for {qname},")
            print(f"    validating that the CNAME was synthesized "
                  f"from {wildcard}.")
        else:
            h_name = nsec3_hash_name(qname, salt_hex, iterations)
            covers2, wrap2 = nsec3_covers(owner_hash, next_hash, h_name)
            if covers2:
                wrap_note = " (wrap-around)" if wrap2 else ""
                print(f"\n    Role: Covers H({qname}){wrap_note}")

        print_nsec3_optout(rdata)


def _explain_nsec_cname_nodata(target, qtype_str, nsec_records, zone):
    """Explain NSEC proving the CNAME target lacks the queried type."""
    qtype_num = dns.rdatatype.from_text(qtype_str) \
        if isinstance(qtype_str, str) else qtype_str

    for owner, nxt, types, rdata in nsec_records:
        print(f"\n  NSEC: {owner} -> {nxt}")
        print(f"    Type bitmap: [{format_types(types)}]")

        if owner == target:
            print(f"\n    Role: Matches the CNAME target ({target})")
            if qtype_num in types:
                print(f"    NOTE: {qtype_str} IS present in the bitmap — "
                      f"unexpected for NODATA")
            else:
                print(f"    The type bitmap does not include {qtype_str}, "
                      f"proving no {qtype_str} record exists at {target}.")
        else:
            if zone:
                covers, wraparound = nsec_covers(owner, nxt, target, zone)
                if covers:
                    wrap_note = " (wrap-around)" if wraparound else ""
                    print(f"\n    Role: Covers the CNAME target "
                          f"({target}){wrap_note}")


def _explain_nsec3_cname_nodata(target, qtype_str, nsec3_records, zone,
                                salt_hex, iterations):
    """Explain NSEC3 proving the CNAME target lacks the queried type."""
    qtype_num = dns.rdatatype.from_text(qtype_str) \
        if isinstance(qtype_str, str) else qtype_str
    h_target = nsec3_hash_name(target, salt_hex, iterations)
    print(f"\n  H({target}) = {h_target}")

    for owner_name, owner_hash, next_hash, types, rdata in nsec3_records:
        print_nsec3_record(owner_hash, next_hash, types, rdata)

        if owner_hash == h_target:
            print(f"\n    Role: Matches H({target}) — the CNAME target")
            if qtype_num in types:
                print(f"    NOTE: {qtype_str} IS present in the bitmap — "
                      f"unexpected for NODATA")
            else:
                print(f"    The type bitmap does not include {qtype_str}, "
                      f"proving no {qtype_str} record exists at {target}.")

            explain_nsec3_cdoe(types)
        else:
            covers, wraparound = nsec3_covers(
                owner_hash, next_hash, h_target)
            if covers:
                wrap_note = " (wrap-around)" if wraparound else ""
                print(f"\n    Role: Covers H({target}){wrap_note}")

        print_nsec3_optout(rdata)


def print_answer_section(response):
    """Print non-RRSIG answer records, if any."""
    records = [rrset for rrset in response.answer
               if rrset.rdtype != dns.rdatatype.RRSIG]
    if not records:
        return
    print(f"\nAnswer section:")
    for rrset in records:
        for rdata in rrset:
            print(f"  {rrset.name} {rrset.ttl} {dns.rdatatype.to_text(rrset.rdtype)} {rdata}")


def decode_response(qname, qtype_str, response):
    """Decode and explain NSEC/NSEC3 records in a DNS response."""
    rcode = response.rcode()

    print_header(qname, qtype_str, rcode, response)

    nsec_records = get_nsec_records(response)
    nsec3_records = get_nsec3_records(response)

    if not nsec_records and not nsec3_records:
        print("\nNo NSEC or NSEC3 records in authority section.")
        return

    zone = find_zone_from_soa(response)
    if not zone:
        zone = find_zone_from_rrsig(response)

    referral = is_referral(response)
    has_data = has_answer_data(response)
    cname_chain, cname_target = get_cname_chain(response, qname)
    cname_nodata = (cname_chain and rcode == dns.rcode.NOERROR
                    and not has_non_cname_answer(response)
                    and (nsec_records or nsec3_records))

    if cname_nodata:
        explain_cname_nodata(qname, qtype_str, cname_chain, cname_target,
                             nsec_records, nsec3_records, response)
        print()
        return

    if zone:
        print(f"Zone: {zone}")

    wildcard = has_data and rcode == dns.rcode.NOERROR and \
        (nsec_records or nsec3_records)
    nodata = rcode == dns.rcode.NOERROR and not has_data and not referral

    if nsec_records:
        if rcode == dns.rcode.NXDOMAIN:
            print(f"\nNXDOMAIN: {qname} does not exist.")
            print(f"\nAuthority section:")
            explain_nsec_nxdomain(qname, nsec_records, zone)
        elif nodata:
            explain_nsec_nodata(qname, qtype_str, nsec_records, zone)
        elif wildcard:
            print(f"\nWildcard-synthesized answer for {qname}.")
            print_answer_section(response)
            print(f"\nAuthority section:")
            explain_nsec_wildcard(qname, nsec_records, zone)
        elif referral:
            print(f"\nReferral (unsigned delegation).")
            print(f"\nAuthority section:")
            explain_nsec_referral(qname, nsec_records, zone)

    elif nsec3_records:
        salt_hex, iterations = print_nsec3_params(nsec3_records)

        if rcode == dns.rcode.NXDOMAIN:
            print(f"\nNXDOMAIN: {qname} does not exist.")
            print(f"\nAuthority section:")
            explain_nsec3_nxdomain(
                qname, nsec3_records, zone, salt_hex, iterations)
        elif nodata:
            explain_nsec3_nodata(
                qname, qtype_str, nsec3_records, zone, salt_hex, iterations)
        elif wildcard:
            print(f"\nWildcard-synthesized answer for {qname}.")
            print_answer_section(response)
            print(f"\nAuthority section:")
            explain_nsec3_wildcard(
                qname, nsec3_records, zone, salt_hex, iterations)
        elif referral:
            print(f"\nReferral (unsigned delegation).")
            print(f"\nAuthority section:")
            explain_nsec3_referral(
                qname, nsec3_records, zone, salt_hex, iterations)

    print()


def decode(qname_str, qtype_str, doh_url=None, resolver_ip=None):
    """Query DNS and decode the response."""
    qname = dns.name.from_text(qname_str)
    response = query_dns(qname, qtype_str, doh_url, resolver_ip)
    decode_response(qname, qtype_str, response)


def main():
    parser = argparse.ArgumentParser(
        description="Decode and explain NSEC/NSEC3 records in DNS responses")
    parser.add_argument("qname", help="Query name")
    parser.add_argument("qtype", help="Query type (e.g., A, AAAA, MX)")
    transport = parser.add_mutually_exclusive_group()
    transport.add_argument("--doh", action="store_true",
                           help="Use DNS-over-HTTPS (default: Cloudflare)")
    transport.add_argument("--doh-server", metavar="URL",
                           help="DoH server URL (implies --doh)")
    transport.add_argument("--resolver", metavar="IP",
                           help="Use this resolver IP address instead of system default")
    args = parser.parse_args()

    doh_url = None
    resolver_ip = None
    if args.doh or args.doh_server:
        doh_url = args.doh_server or DEFAULT_DOH_URL
    elif args.resolver:
        resolver_ip = args.resolver

    qname = args.qname
    if not qname.endswith('.'):
        qname += '.'

    try:
        decode(qname, args.qtype, doh_url, resolver_ip)
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
