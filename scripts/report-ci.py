#!/usr/bin/env python3
"""Expose bounded test/catalog diagnostics through GitHub check annotations.

This keeps native failures readable through the Checks API as well as full logs.
Never includes environment variables, authentication tokens or private key files.
"""
import argparse
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def escape(value):
    return str(value).replace('%','%25').replace('\r','%0D').replace('\n','%0A')


def annotation(level,title,message):
    message=str(message)
    if len(message)>3500:message=message[:500]+'\n...bounded traceback; full details in artifact...\n'+message[-2900:]
    print(f'::{level} title={escape(title).replace(",","%2C").replace(":","%3A")}::{escape(message)}')


def report_junit(path):
    root=ET.fromstring(path.read_bytes())
    cases=list(root.iter('testcase'))
    failed=0;skipped=0
    for case in cases:
        if case.find('skipped') is not None:skipped+=1
        for kind in ('failure','error'):
            reason=case.find(kind)
            if reason is not None:
                failed+=1
                annotation('error',case.get('name','Test failure'),reason.text or reason.get('message','No diagnostic was recorded.'))
    annotation('notice','Test results',f'{len(cases)} cases; {failed} failures/errors; {skipped} skipped; source {path.name}.')


def report_catalog(path):
    for row in json.loads(path.read_text()):
        level='notice' if row['verified'] else ('warning' if row['lifecycle_warning'] else 'error')
        annotation(level,'OS endpoint: '+row['id'],row['url']+'\n'+('VERIFIED HTTPS QCOW2 endpoint' if row['verified'] else row['error']))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kind',choices=('junit','catalog'))
    parser.add_argument('path',type=Path)
    args=parser.parse_args()
    if not args.path.is_file():
        annotation('warning','Acceptance evidence missing',f'{args.path.name} was not produced. The prior step did not complete; this is not a passing native test.')
        return
    if args.path.stat().st_size>8*2**20:raise ValueError('Diagnostic report exceeds the safe 8 MiB limit.')
    (report_junit if args.kind=='junit' else report_catalog)(args.path)


if __name__=='__main__':main()
