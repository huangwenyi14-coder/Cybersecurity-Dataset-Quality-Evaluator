"""Small shared Markdown rendering helpers."""
from pathlib import Path
from metric_catalog import METRICS

def table(headers,rows):
    def cell(x):return str(x).replace('|',' / ').replace('\n',' ')
    return '\n'.join(['| '+' | '.join(headers)+' |','| '+' | '.join(['---']*len(headers))+' |']+
                     ['| '+' | '.join(cell(x) for x in r)+' |' for r in rows])+'\n'

def link(p,title=None):
    return f'[{title or Path(p).name}](<{Path(p).resolve().as_posix()}>)'

NAMES = {k:v[2] for k,v in METRICS.items() if k.startswith('C')}
