#!/usr/bin/env python3
"""Print an Ubuntu cloud-image SHA256 only after verifying the vendor GPG signature.

Uses a distribution-provided trusted ubuntu-cloudimage-keyring, NEVER a key
fetched alongside the checksum. No app/production database or private key needed.
"""
import argparse
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import requests

RELEASES={'ubuntu-22.04':'jammy','ubuntu-24.04':'noble'}


def checksum_entry(manifest,filename):
    matches=[]
    for line in manifest.splitlines():
        matched=re.fullmatch(r'([a-fA-F0-9]{64})[ \t]+\*?(?:\./)?([^/\s]+)',line)
        if matched and matched[2]==filename:matches.append(matched[1].lower())
    if len(matches)!=1:raise ValueError('Signed manifest must contain exactly one checksum for the selected image.')
    return matches[0]


def download(session,url):
    with session.get(url,timeout=(10,20),stream=True,allow_redirects=False) as response:
        if response.status_code!=200:raise ValueError(f'Vendor manifest request failed with HTTP {response.status_code}; no redirects or insecure fallback allowed.')
        result=bytearray()
        # read1 avoids waiting to fill a requested chunk when a server trickles data.
        while block:=response.raw.read1(16384,decode_content=True):
            result.extend(block)
            if len(result)>2**20:raise ValueError('Vendor checksum/signature exceeded the 1 MiB limit.')
        return bytes(result)


def verified_checksum(release,keyring):
    keyring=Path(keyring).resolve(strict=True)
    if not keyring.is_file() or not shutil.which('gpgv'):
        raise ValueError('gpgv and a trusted distribution Ubuntu cloud-image keyring are required.')
    codename=RELEASES[release]
    base=f'https://cloud-images.ubuntu.com/{codename}/current/'
    with requests.Session() as session:
        session.trust_env=False
        manifest=download(session,base+'SHA256SUMS')
        signature=download(session,base+'SHA256SUMS.gpg')
    with tempfile.TemporaryDirectory(prefix='skvm-signed-checksum-') as directory:
        root=Path(directory);(root/'SHA256SUMS').write_bytes(manifest);(root/'SHA256SUMS.gpg').write_bytes(signature)
        result=subprocess.run(['gpgv','--homedir',str(root),'--keyring',str(keyring),str(root/'SHA256SUMS.gpg'),str(root/'SHA256SUMS')],
                              capture_output=True,text=True,timeout=30,check=False)
        if result.returncode:raise ValueError('Ubuntu checksum signature did not verify against the trusted distribution keyring; no image was accepted. '+result.stderr[-1200:])
    return checksum_entry(manifest.decode('utf-8'),f'{codename}-server-cloudimg-amd64.img')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--os-id',choices=RELEASES,default='ubuntu-24.04')
    parser.add_argument('--keyring',default='/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg')
    args=parser.parse_args()
    try:print(verified_checksum(args.os_id,args.keyring))
    except (ValueError,OSError,requests.RequestException,subprocess.SubprocessError) as exc:
        print(str(exc),file=sys.stderr);return 1
    return 0


if __name__=='__main__':raise SystemExit(main())
