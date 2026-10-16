import shutil
from pathlib import Path

root = Path(__file__).resolve().parents[1]
shutil.copyfile(root / 'evidence/ci-summary.json', root / 'web/proof.json')
