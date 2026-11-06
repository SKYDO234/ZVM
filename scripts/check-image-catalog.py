#!/usr/bin/env python3
"""Live-check all nine vendor candidates in a disposable DB, never production state."""
import argparse
import json
from pathlib import Path
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from engines import EngineError
from extensions import db
from models import OSImage
from services.image_manager import ImageManager
from skvm import create_app


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report',type=Path)
    parser.add_argument('--strict',action='store_true',help='Fail if a non-EOL catalog endpoint cannot be verified.')
    args=parser.parse_args();results=[]
    with tempfile.TemporaryDirectory(prefix='skvm-catalog-check-') as directory:
        root=Path(directory)
        app=create_app({'DATA_DIR':root/'data','SQLALCHEMY_DATABASE_URI':f'sqlite:///{root/"catalog.db"}','START_WORKER':False})
        with app.app_context():
            for image in db.session.scalars(db.select(OSImage).order_by(OSImage.id)):
                error=None
                try:ImageManager().verify(image)
                except EngineError as exc:error=str(exc)
                result={'id':image.id,'url':image.qemu_url,'verified':error is None,'error':error,'lifecycle_warning':image.eol_warning}
                results.append(result)
                print(f'{image.id}: '+('VERIFIED QCOW2 endpoint' if error is None else 'UNAVAILABLE: '+error))
            db.session.remove();db.engine.dispose()
    if args.report:
        args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(results,indent=2))
    return int(args.strict and any(not r['verified'] and not r['lifecycle_warning'] for r in results))


if __name__=='__main__':raise SystemExit(main())
