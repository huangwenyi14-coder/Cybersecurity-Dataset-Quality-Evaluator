"""Build a source-only ZIP using an explicit allowlist; never include local .env."""
from pathlib import Path
import argparse, hashlib, json, re, zipfile

ROOT=Path(__file__).resolve().parent.parent
ROOT_FILES={'README.md','.gitignore','.env.example','requirements.txt','run.py','run_tests.py'}
DIRECTORIES={'src','resources','docs','tests','scripts','.github'}
EXTENSIONS={'.py','.json','.md','.txt','.yml','.yaml'}

def release_files(root=ROOT):
    root=Path(root).resolve();chosen=[]
    for name in sorted(ROOT_FILES):
        p=root/name
        if not p.is_file():raise ValueError('Required release file missing: '+name)
        chosen.append(p)
    for directory in sorted(DIRECTORIES):
        for p in sorted((root/directory).rglob('*')):
            if not p.is_file() or '__pycache__' in p.parts:continue
            if p.suffix not in EXTENSIONS:continue
            if p.is_symlink() or not p.resolve().is_relative_to(root):raise ValueError('Release file leaves project')
            chosen.append(p)
    for p in chosen:
        if p.is_symlink() or not p.resolve().is_relative_to(root):raise ValueError('Release file leaves project')
        text=p.read_text(encoding='utf-8')
        if re.search(r'\bsk-[A-Za-z0-9_-]{20,}\b',text):raise ValueError('Potential credential in release file: '+p.relative_to(root).as_posix())
        if re.search(r'[A-Za-z]:[\\/]+Users[\\/]',text):raise ValueError('Personal absolute path in release file: '+p.relative_to(root).as_posix())
    return chosen

def package(output,root=ROOT):
    root=Path(root).resolve();output=Path(output).expanduser().resolve()
    files=release_files(root)
    if output.exists():raise ValueError('Release destination exists; no overwrite')
    output.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_DEFLATED) as archive:
        for p in files:archive.write(p,p.relative_to(root).as_posix())
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None:raise ValueError('ZIP integrity check failed')
        assert '.env' not in archive.namelist()
        for p in files:
            assert archive.read(p.relative_to(root).as_posix())==p.read_bytes()
    return {'output':str(output),'files':len(files),'bytes':output.stat().st_size,
            'sha256':hashlib.sha256(output.read_bytes()).hexdigest(),'credentials_and_datasets_included':False}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(package(args.output),ensure_ascii=False))
