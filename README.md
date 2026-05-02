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

- Python 3.9+
- [dnspython](https://www.dnspython.org/) (`pip install dnspython`)
- For DoH support: `pip install dnspython[doh]`


## Installation

```
pip install .
```

Or directly from the GitHub repository:

```
pip install git+https://github.com/shuque/decode_nsec_response.git
```

This installs the `decode_nsec_response.py` script and its dependencies.

For a system-wide install:

```
sudo pip install .
```

On systems where pip is restricted from modifying the system Python
environment (Debian/Ubuntu with PEP 668), use one of:

```
sudo pip install --break-system-packages .
sudo pip install --prefix=/usr/local .
```


## Testing

The test suite uses canned DNS responses in wire format, so tests run
instantly and are not affected by live DNS changes.

**Capture test data** (only needed when adding or refreshing test cases):

```
python3 capture_test_data.py
```

This queries all 14 test cases via DoH to Cloudflare and saves the raw
wire bytes to `testdata/`.

**Run the test suite:**

```
python3 -m unittest test_decode -v
```

Or with pytest if installed:

```
python3 -m pytest test_decode.py -v
```


## Sample Output

NSEC3 NODATA:

```
$ ./decode_nsec_response.py --doh salesforce.com. TLSA

Query: salesforce.com. TLSA
Response: NOERROR [AD]
======================================================================
Zone: salesforce.com.
NSEC3 params: algorithm 1, iterations 0, salt 7FEA7B83

  H(salesforce.com.) = 49STKNJU01HOVPN0L8N7MMD35E9VD3VD

NODATA: salesforce.com. exists but has no TLSA record.

Authority section:

  NSEC3: 49STKNJU01HOVPN0L8N7MMD35E9VD3VD -> 49T2A4TT2OHA06O3HB89B4PCF7U0824L
    Type bitmap: [A NS SOA MX TXT RRSIG DNSKEY NSEC3PARAM TYPE65534]

    Role: Matches H(salesforce.com.)
    The type bitmap does not include TLSA, proving no TLSA record exists at this name.
```

NSEC3 NXDOMAIN:

```
$ ./decode_nsec_response.py --doh foo.nxd123.salesforce.com. A

Query: foo.nxd123.salesforce.com. A
Response: NXDOMAIN [AD]
======================================================================
Zone: salesforce.com.
NSEC3 params: algorithm 1, iterations 0, salt 7FEA7B83

NXDOMAIN: foo.nxd123.salesforce.com. does not exist.

Authority section:

  Closest encloser: salesforce.com.
  Next closer name: nxd123.salesforce.com.
  Wildcard at CE:   *.salesforce.com.
  H(salesforce.com.) = 49STKNJU01HOVPN0L8N7MMD35E9VD3VD
  H(nxd123.salesforce.com.) = JP5FLA1OE214J8NI0E55A3GVP96NGINB
  H(*.salesforce.com.) = 09UJ9K6OKDGIKMN908E3ULJRDMKM277V

  NSEC3: 49STKNJU01HOVPN0L8N7MMD35E9VD3VD -> 49T2A4TT2OHA06O3HB89B4PCF7U0824L
    Type bitmap: [A NS SOA MX TXT RRSIG DNSKEY NSEC3PARAM TYPE65534]

    Role: Matches H(salesforce.com.) — closest encloser proof
    Proves salesforce.com. exists in the zone.

  NSEC3: JP1PCI1BBC6Q7F8136EPU4LT4CUEPNTM -> JP6FI3JBGQTR23BALRE30LG9UFU3FJHJ
    Type bitmap: [A RRSIG]

    Role: Covers H(nxd123.salesforce.com.) — next closer name cover
    Proves nxd123.salesforce.com. does not exist.

  NSEC3: 09TD20B1LCISV1SUHEMNIUCF1FGB5K26 -> 09UJ9OKA6O2IRL1I3Q0D193ERNT3P0I6
    Type bitmap: [A RRSIG]

    Role: Covers H(*.salesforce.com.) — wildcard cover
    Proves no wildcard exists at the closest encloser (salesforce.com.),
    so no wildcard synthesis can produce an answer.
```

NSEC3 Wildcard Match:

```
$ ./decode_nsec_response.py --doh foo.wild.dnskensa.com. A

Query: foo.wild.dnskensa.com. A
Response: NOERROR [AD]
======================================================================
Zone: dnskensa.com.
NSEC3 params: algorithm 1, iterations 10, salt 73B2182A738FCBC4

Wildcard-synthesized answer for foo.wild.dnskensa.com..

Answer section:
  foo.wild.dnskensa.com. 86400 A 10.1.1.1

Authority section:

  Closest encloser: wild.dnskensa.com.
  Next closer name: foo.wild.dnskensa.com.
  Wildcard:         *.wild.dnskensa.com.
  H(foo.wild.dnskensa.com.) = 3BPL37FUV6JQLG6BLVIRV23T5JVP1H4L

  NSEC3: 33OE6CIJFV452QC67M4A72F474I3M2E5 -> 3F3DEH8FT59Q4S2MNVN446MFALKSAFSU
    Type bitmap: [A AAAA RRSIG]

    Role: Covers H(foo.wild.dnskensa.com.) — next closer name cover
    Proves no closer match than wild.dnskensa.com. exists for foo.wild.dnskensa.com.,
    validating that the answer was synthesized from a wildcard.
```

NSEC NXDOMAIN:

```
$ ./decode_nsec_response.py --doh foobar. A

Query: foobar. A
Response: NXDOMAIN [AD]
======================================================================
Zone: .

NXDOMAIN: foobar. does not exist.

Authority section:

  NSEC: foo. -> food.
    Type bitmap: [NS DS RRSIG NSEC]

    Role: Covers the queried name (foobar.)
    Owner sorts before qname, next sorts after qname
    in canonical order, proving foobar. does not exist.

  NSEC: . -> aaa.
    Type bitmap: [NS SOA RRSIG NSEC DNSKEY ZONEMD]

    Role: Covers the wildcard (*.)
    Proves no wildcard exists at the closest encloser (.),
    so no wildcard synthesis can produce an answer.
```

Wildcard CNAME NODATA (cross-zone; NSEC3 wildcard proof + NSEC target NODATA):

```
$ ./decode_nsec_response.py --doh 12345asdfasfadf.horoscope-divination.com. AFSDB

Query: 12345asdfasfadf.horoscope-divination.com. AFSDB
Response: NOERROR [AD]
======================================================================

Wildcard CNAME NODATA: 12345asdfasfadf.horoscope-divination.com. matched wildcard *.horoscope-divination.com.,
which targets general-beetle-fec22eecz21z3tnuxbx8mde3.herokudns.com.. The target has no AFSDB record.

Answer section:
  12345asdfasfadf.horoscope-divination.com. 600 CNAME general-beetle-fec22eecz21z3tnuxbx8mde3.herokudns.com.

Authority section:

  --- Wildcard proof (zone: horoscope-divination.com.) ---
NSEC3 params: algorithm 1, iterations 0, salt D54DF1360676F4B8

  Closest encloser: horoscope-divination.com.
  Next closer name: 12345asdfasfadf.horoscope-divination.com.
  Wildcard:         *.horoscope-divination.com.
  H(12345asdfasfadf.horoscope-divination.com.) = V24NHP56RH0DS80NDKCVTMVU9BC4IR0M

  NSEC3: UOLUGA2L16M65IELFLBNLEM2V8COSCI6 -> 28DNC0LB8B15CTN3GTIRT1RJDR0P16R7
    Type bitmap: [A RRSIG]

    Role: Covers H(12345asdfasfadf.horoscope-divination.com.) — next closer name cover (wrap-around)
    Proves no closer match than horoscope-divination.com. exists for 12345asdfasfadf.horoscope-divination.com.,
    validating that the CNAME was synthesized from *.horoscope-divination.com..

  --- NODATA proof (zone: herokudns.com.) ---

  NSEC: general-beetle-fec22eecz21z3tnuxbx8mde3.herokudns.com. -> \000.general-beetle-fec22eecz21z3tnuxbx8mde3.herokudns.com.
    Type bitmap: [A AAAA RRSIG NSEC]

    Role: Matches the CNAME target (general-beetle-fec22eecz21z3tnuxbx8mde3.herokudns.com.)
    The type bitmap does not include AFSDB, proving no AFSDB record exists at general-beetle-fec22eecz21z3tnuxbx8mde3.herokudns.com..
```
