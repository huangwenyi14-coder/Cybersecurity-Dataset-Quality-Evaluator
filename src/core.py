from pathlib import Path
import csv, json, gzip, hashlib, datetime, os
from collections import Counter, defaultdict
import orjson

BASE=Path(__file__).resolve().parent
ROOT=BASE.parent
RES=ROOT/'resources'

def read(p):return orjson.loads(Path(p).read_bytes())
def save(p,x):
 p=Path(p);p.parent.mkdir(parents=True,exist_ok=True);tmp=p.with_suffix(p.suffix+'.tmp');tmp.write_bytes(orjson.dumps(x,option=orjson.OPT_INDENT_2|orjson.OPT_NON_STR_KEYS))
 # Windows readers / antivirus can temporarily deny atomic replacement of an open file.
 import time
 for attempt in range(10):
  try:os.replace(tmp,p);return
  except PermissionError:
   if attempt==9:raise
   time.sleep(min(.02*2**attempt,.3))
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
def unwrap(x):return next(iter(x.values())) if isinstance(x,dict) and len(x)==1 else x
def rows(p):
 with Path(p).open(encoding='utf-8-sig',newline='') as f:return [{k.strip():v.strip() for k,v in r.items()} for r in csv.DictReader(f,skipinitialspace=True)]
def lines(p):
 with gzip.open(p,'rb') as f:
  for line in f:yield orjson.loads(line)
def emit(f,x):f.write(orjson.dumps(x)+b'\n')
def stamp():return datetime.datetime.now(datetime.timezone.utc).isoformat()
