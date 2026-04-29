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

import dns.name
import dns.query
import dns.message
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.flags
import dns.dnssec

DEFAULT_DOH_URL = "https://cloudflare-dns.com/dns-query"

NXNAME_TYPE = 128


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


def canonical_order_less(name1, name2, origin):
    """Compare two names in DNS canonical order within a zone."""
    rel1 = name1.relativize(origin)
    rel2 = name2.relativize(origin)
    return rel1.canonicalize() < rel2.canonicalize()


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


def has_answer_data(response):
    """Check if the response has non-RRSIG answer records."""
    return any(
        rrset.rdtype != dns.rdatatype.RRSIG
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

            cdoe_next = dns.name.Name((b'\x00',) + qname.labels)
            if nxt == cdoe_next:
                nxname = NXNAME_TYPE in types
                real_types = types - {dns.rdatatype.RRSIG,
                                      dns.rdatatype.NSEC, NXNAME_TYPE}
                if nxname:
                    print(f"\n    Pattern: Compact Denial of Existence "
                          f"(RFC 9824)")
                    print(f"    Next name = \\000.{qname} (CDoE "
                          f"signature)")
                    print(f"    NXNAME (TYPE128) present — name does "
                          f"not exist")
                elif not real_types:
                    print(f"\n    Pattern: Compact Denial of Existence "
                          f"(RFC 9824)")
                    print(f"    Next name = \\000.{qname} (CDoE "
                          f"signature)")
                    print(f"    Bitmap has no real types — likely "
                          f"CDoE without NXNAME")
                else:
                    print(f"\n    Next name = \\000.{qname}")
                    print(f"    This name has children in the zone; "
                          f"the \\000 child label ensures the NSEC")
                    print(f"    range does not cover existing child "
                          f"names.")
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

    for owner_name, owner_hash, next_hash, types, rdata in nsec3_records:
        opt_out = " [OPT-OUT]" if rdata.flags & 0x01 else ""
        print(f"\n  NSEC3: {owner_hash} -> {next_hash}{opt_out}")
        print(f"    Type bitmap: [{format_types(types)}]")

        if owner_hash == h_qname:
            print(f"\n    Role: Matches H({qname})")

            if isinstance(qtype_str, str):
                if qtype_num in types:
                    print(f"    NOTE: {qtype_str} IS present in the "
                          f"bitmap — unexpected for NODATA")
                else:
                    print(f"    The type bitmap does not include "
                          f"{qtype_str}, proving no {qtype_str} record "
                          f"exists at this name.")

            cdoe_types = types - {dns.rdatatype.RRSIG, dns.rdatatype.NSEC3}
            has_nxname = NXNAME_TYPE in cdoe_types
            is_minimal = cdoe_types <= {NXNAME_TYPE}

            if is_minimal:
                print(f"\n    Pattern: Compact Denial of Existence with "
                      f"NSEC3 (RFC 9824 Section 4)")
                if has_nxname:
                    print(f"    NXNAME (TYPE128) present — name does "
                          f"not exist")
                else:
                    print(f"    Minimal bitmap (no real types) — likely "
                          f"CDoE without NXNAME")
        else:
            covers, wraparound = nsec3_covers(
                owner_hash, next_hash, h_qname)
            if covers:
                wrap_note = " (wrap-around)" if wraparound else ""
                print(f"\n    Role: Covers H({qname}){wrap_note}")

        if rdata.flags & 0x01:
            print(f"    Opt-out flag set: unsigned delegations may "
                  f"exist within this range.")


def explain_nsec3_nxdomain(qname, nsec3_records, zone, salt_hex, iterations):
    """Explain NSEC3 records in an NXDOMAIN response."""
    h_qname = nsec3_hash_name(qname, salt_hex, iterations)
    print(f"\n  H({qname}) = {h_qname}")

    candidates = []
    name = qname
    while name.is_subdomain(zone):
        candidates.append(name)
        name = name.parent()

    ce_found = None
    ce_name = None
    ncn_found = None
    wc_found = None
    wc_name = None

    for candidate in reversed(candidates):
        h_candidate = nsec3_hash_name(candidate, salt_hex, iterations)
        for owner_name, owner_hash, next_hash, types, rdata in nsec3_records:
            if owner_hash == h_candidate:
                ce_found = (owner_name, owner_hash, next_hash, types, rdata)
                ce_name = candidate

                ncn_idx = candidates.index(candidate) - 1
                if ncn_idx >= 0:
                    ncn_name = candidates[ncn_idx]
                    h_ncn = nsec3_hash_name(ncn_name, salt_hex, iterations)
                    wc_test = dns.name.Name((b'*',) + candidate.labels)
                    h_wc = nsec3_hash_name(wc_test, salt_hex, iterations)

                    for on, oh, nh, ty, rd in nsec3_records:
                        covers, _ = nsec3_covers(oh, nh, h_ncn)
                        if covers:
                            ncn_found = (on, oh, nh, ty, rd, ncn_name, h_ncn)
                        covers_wc, _ = nsec3_covers(oh, nh, h_wc)
                        if covers_wc and oh != owner_hash:
                            wc_found = (on, oh, nh, ty, rd,
                                        wc_test, h_wc)
                break

    if ce_name:
        rel = qname.relativize(ce_name)
        ncn_full = dns.name.Name((rel.labels[-1],) + ce_name.labels)
        print(f"\n  Closest encloser: {ce_name}")
        print(f"  Next closer name: {ncn_full}")
        wc_at_ce = dns.name.Name((b'*',) + ce_name.labels)
        print(f"  Wildcard at CE:   {wc_at_ce}")
        h_wc_ce = nsec3_hash_name(wc_at_ce, salt_hex, iterations)
        print(f"  H({wc_at_ce}) = {h_wc_ce}")
        if ncn_found:
            print(f"  H({ncn_found[5]}) = {ncn_found[6]}")

    for owner_name, owner_hash, next_hash, types, rdata in nsec3_records:
        opt_out = " [OPT-OUT]" if rdata.flags & 0x01 else ""
        print(f"\n  NSEC3: {owner_hash} -> {next_hash}{opt_out}")
        print(f"    Type bitmap: [{format_types(types)}]")

        if ce_found and owner_hash == ce_found[1]:
            print(f"\n    Role: Matches H({ce_name}) — closest encloser "
                  f"proof")
            print(f"    Proves {ce_name} exists in the zone.")

        elif ncn_found and owner_hash == ncn_found[1] \
                and next_hash == ncn_found[2]:
            ncn_name = ncn_found[5]
            h_ncn = ncn_found[6]
            _, wraparound = nsec3_covers(owner_hash, next_hash, h_ncn)
            wrap_note = " (wrap-around)" if wraparound else ""
            print(f"\n    Role: Covers H({ncn_name}) — next closer name "
                  f"cover{wrap_note}")
            print(f"    Proves {ncn_name} does not exist.")

        elif wc_found and owner_hash == wc_found[1] \
                and next_hash == wc_found[2]:
            wc_n = wc_found[5]
            h_wc = wc_found[6]
            _, wraparound = nsec3_covers(owner_hash, next_hash, h_wc)
            wrap_note = " (wrap-around)" if wraparound else ""
            print(f"\n    Role: Covers H({wc_n}) — wildcard "
                  f"cover{wrap_note}")
            print(f"    Proves no wildcard exists at the closest "
                  f"encloser ({ce_name}),")
            print(f"    so no wildcard synthesis can produce an answer.")

        else:
            covers, wraparound = nsec3_covers(
                owner_hash, next_hash, h_qname)
            if covers:
                wrap_note = " (wrap-around)" if wraparound else ""
                print(f"\n    Role: Covers H({qname}){wrap_note}")

        if rdata.flags & 0x01:
            print(f"    Opt-out flag set: unsigned delegations may "
                  f"exist within this range.")

    if not ce_found:
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
    h_qname = nsec3_hash_name(qname, salt_hex, iterations)
    print(f"\n  H({qname}) = {h_qname}")

    for owner_name, owner_hash, next_hash, types, rdata in nsec3_records:
        opt_out = " [OPT-OUT]" if rdata.flags & 0x01 else ""
        print(f"\n  NSEC3: {owner_hash} -> {next_hash}{opt_out}")
        print(f"    Type bitmap: [{format_types(types)}]")

        covers, wraparound = nsec3_covers(owner_hash, next_hash, h_qname)
        if covers:
            wrap_note = " (wrap-around)" if wraparound else ""
            print(f"\n    Role: Covers H({qname}) — next closer name "
                  f"cover{wrap_note}")
            print(f"    Proves no exact match exists for {qname},")
            print(f"    validating that the answer was synthesized "
                  f"from a wildcard.")
        else:
            candidates = []
            name = qname.parent()
            while name.is_subdomain(zone):
                candidates.append(name)
                name = name.parent()
            for ce in candidates:
                ncn = dns.name.Name(
                    (qname.relativize(ce).labels[0],) + ce.labels)
                h_ncn = nsec3_hash_name(ncn, salt_hex, iterations)
                cov, wrap = nsec3_covers(owner_hash, next_hash, h_ncn)
                if cov:
                    wrap_note = " (wrap-around)" if wrap else ""
                    print(f"\n    Role: Covers H({ncn}){wrap_note}")
                    print(f"    H({ncn}) = {h_ncn}")
                    break

        if rdata.flags & 0x01:
            print(f"    Opt-out flag set: unsigned delegations may "
                  f"exist within this range.")


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
        opt_out = " [OPT-OUT]" if rdata.flags & 0x01 else ""
        print(f"\n  NSEC3: {owner_hash} -> {next_hash}{opt_out}")
        print(f"    Type bitmap: [{format_types(types)}]")

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

        if rdata.flags & 0x01:
            print(f"    Opt-out flag set: unsigned delegations may "
                  f"exist within this range.")


def decode(qname_str, qtype_str, doh_url=None, resolver_ip=None):
    """Main decode routine."""
    qname = dns.name.from_text(qname_str)
    response = query_dns(qname, qtype_str, doh_url, resolver_ip)
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

    if zone:
        print(f"Zone: {zone}")

    referral = is_referral(response)
    has_data = has_answer_data(response)
    wildcard = has_data and rcode == dns.rcode.NOERROR and \
        (nsec_records or nsec3_records)
    nodata = rcode == dns.rcode.NOERROR and not has_data and not referral

    if nsec_records:
        if rcode == dns.rcode.NXDOMAIN:
            print(f"\nNXDOMAIN: {qname} does not exist.")
            explain_nsec_nxdomain(qname, nsec_records, zone)
        elif nodata:
            print(f"\nNODATA: {qname} exists but has no {qtype_str} record.")
            explain_nsec_nodata(qname, qtype_str, nsec_records, zone)
        elif wildcard:
            print(f"\nWildcard-synthesized answer for {qname}.")
            explain_nsec_wildcard(qname, nsec_records, zone)
        elif referral:
            print(f"\nReferral (unsigned delegation).")
            explain_nsec_referral(qname, nsec_records, zone)

    elif nsec3_records:
        params = get_nsec3_params(nsec3_records[0][4])
        algo, flags, iterations, salt_hex = params
        salt_display = salt_hex if salt_hex != '-' else '(empty)'
        print(f"NSEC3 params: algorithm {algo}, iterations {iterations}, "
              f"salt {salt_display}")

        if rcode == dns.rcode.NXDOMAIN:
            print(f"\nNXDOMAIN: {qname} does not exist.")
            explain_nsec3_nxdomain(
                qname, nsec3_records, zone, salt_hex, iterations)
        elif nodata:
            print(f"\nNODATA: {qname} exists but has no {qtype_str} record.")
            explain_nsec3_nodata(
                qname, qtype_str, nsec3_records, zone, salt_hex, iterations)
        elif wildcard:
            print(f"\nWildcard-synthesized answer for {qname}.")
            explain_nsec3_wildcard(
                qname, nsec3_records, zone, salt_hex, iterations)
        elif referral:
            print(f"\nReferral (unsigned delegation).")
            explain_nsec3_referral(
                qname, nsec3_records, zone, salt_hex, iterations)

    print()


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
