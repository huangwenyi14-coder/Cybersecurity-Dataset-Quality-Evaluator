"""Stage archive members safely under the engineering run, without touching input."""
from core import *
import tarfile,zipfile,shutil

def safe_files(root):
 from input_adapters import SKIP
 for base,dirs,names in os.walk(root,followlinks=False):
  dirs[:]=[d for d in dirs if d not in SKIP and not Path(base,d).is_symlink() and not getattr(Path(base,d),'is_junction',lambda:False)()]
  for n in names:
   p=Path(base,n)
   if not p.is_symlink() and p.resolve().is_relative_to(root):yield p

def materialize(root,out):
 root=Path(root).resolve();out=Path(out)
 files=list(safe_files(root));archives=[p for p in files if p.name.lower().endswith(('.tar.gz','.tgz','.tar','.zip'))]
 if not archives:return root,[]
 dest=out/'source';dest.mkdir(parents=True);manifest=[]
 for p in sorted(files):
  rel=p.relative_to(root)
  if p not in archives:
   target=dest/rel;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,target);manifest.append({'input':str(p),'sha256':sha(p),'output':str(target)});continue
  prefix=dest/rel.parent/p.name.replace('.tar.gz','').replace('.tgz','').replace('.tar','').replace('.zip','')
  if p.name.lower().endswith('.zip'):
   z=zipfile.ZipFile(p);members=[(x.filename,x.file_size,lambda x=x:z.open(x)) for x in z.infolist() if not x.is_dir()]
   if any((x.external_attr>>16)&0o170000==0o120000 for x in z.infolist()):raise ValueError('Archive symlinks not accepted')
  else:
   z=tarfile.open(p);members=[]
   for x in z.getmembers():
    if x.isdir():continue
    if not x.isfile():raise ValueError('Archive links/devices not accepted')
    members.append((x.name,x.size,lambda x=x:z.extractfile(x)))
  required=sum(x[1] for x in members)
  if required>shutil.disk_usage(out).free-256*1024**2:raise ValueError('Insufficient space for safe archive staging')
  seen=set()
  try:
   for name,size,opener in members:
    candidate=Path(name.replace('\\','/'))
    if candidate.is_absolute() or '..' in candidate.parts or ':' in name:raise ValueError('Unsafe archive member '+name)
    target=(prefix/candidate).resolve()
    if not target.is_relative_to(dest.resolve()) or target in seen or target.exists():raise ValueError('Archive path collision')
    seen.add(target);target.parent.mkdir(parents=True,exist_ok=True);h=hashlib.sha256();n=0
    with opener() as f,target.open('wb') as w:
     for b in iter(lambda:f.read(1024**2),b''):w.write(b);h.update(b);n+=len(b)
    if n!=size:raise ValueError('Archive member length mismatch')
    manifest.append({'archive':str(p),'member':name,'bytes':n,'sha256':h.hexdigest(),'output':str(target)})
  finally:z.close()
  manifest.append({'archive':str(p),'archive_sha256':sha(p)})
 # Collapse common archive wrappers, preserving all actual files.
 while True:
  entries=list(dest.iterdir())
  if len(entries)==1 and entries[0].is_dir():dest=entries[0]
  else:break
 save(out/'archive_manifest.json',manifest);return dest,manifest
