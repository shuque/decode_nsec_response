# NSEC/NSEC3 Response Decoder

## Description

[decode\_nsec\_response.py](decode_nsec_response.py) — Queries a given
name and type, then decodes and explains the NSEC or NSEC3 records in
the authority section of the response. Identifies the role of each
record in the authenticated denial proof:

- **NXDOMAIN (NSEC)**: which NSEC covers the queried name and which
  covers the wildcard at the closest encloser, with wrap-around
  detection.
- **NXDOMAIN (NSEC3)**: computes NSEC3 hashes and identifies the
  closest encloser match, next closer name cover, and wildcard cover.
- **NODATA**: explains how the type bitmap proves the queried type
  does not exist.
- **Wildcard synthesis**: identifies the NSEC/NSEC3 proving no closer
  name exists, validating the wildcard match. Handles wildcard NODATA
  (wildcard exists but lacks the queried type).
- **Compact Denial of Existence**: detects both NSEC (RFC 9824) and
  NSEC3 (RFC 9824 Section 4) CDoE patterns, with or without NXNAME.
- **Names with children**: explains the `\000` child label successor
  used for names that have children in the zone.
- **NSEC3 opt-out**: flags opt-out NSEC3 records and notes that
  unsigned delegations may exist within the covered range.
- **Referrals**: annotates NSEC/NSEC3 records proving unsigned
  delegations (no DS).

```
./decode_nsec_response.py [--doh] [--doh-server URL] QNAME QTYPE
```

## Dependencies

- Python 3
- [dnspython](https://www.dnspython.org/) (`pip install dnspython`)
- For DoH support: `pip install dnspython[doh]`


## Sample Output

```
$ ./decode_nsec_response.py foo.nxd123.salesforce.com. A

Query: foo.nxd123.salesforce.com. A
Response: NXDOMAIN [AD]
======================================================================
Zone: salesforce.com.
NSEC3 params: algorithm 1, iterations 0, salt 7FEA7B83

NXDOMAIN: foo.nxd123.salesforce.com. does not exist.

  H(foo.nxd123.salesforce.com.) = AKUR0L7SAG0B3G4PJ8BSVS1BE6CKAQTD

  Closest encloser: salesforce.com.
  Next closer name: nxd123.salesforce.com.
  Wildcard at CE:   *.salesforce.com.
  H(*.salesforce.com.) = 09UJ9K6OKDGIKMN908E3ULJRDMKM277V
  H(nxd123.salesforce.com.) = JP5FLA1OE214J8NI0E55A3GVP96NGINB

  NSEC3: 09TD20B1LCISV1SUHEMNIUCF1FGB5K26 -> 09UJ9OKA6O2IRL1I3Q0D193ERNT3P0I6
    Type bitmap: [A RRSIG]

    Role: Covers H(*.salesforce.com.) — wildcard cover
    Proves no wildcard exists at the closest encloser (salesforce.com.),
    so no wildcard synthesis can produce an answer.

  NSEC3: 49STKNJU01HOVPN0L8N7MMD35E9VD3VD -> 49T2A4TT2OHA06O3HB89B4PCF7U0824L
    Type bitmap: [A NS SOA MX TXT RRSIG DNSKEY NSEC3PARAM TYPE65534]

    Role: Matches H(salesforce.com.) — closest encloser proof
    Proves salesforce.com. exists in the zone.

  NSEC3: JP1PCI1BBC6Q7F8136EPU4LT4CUEPNTM -> JP6FI3JBGQTR23BALRE30LG9UFU3FJHJ
    Type bitmap: [A RRSIG]

    Role: Covers H(nxd123.salesforce.com.) — next closer name cover
    Proves nxd123.salesforce.com. does not exist.
```
