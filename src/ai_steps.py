"""General GT-step comparison with bounded raw-log evidence and checked citations."""
from core import *
from input_adapters import records,xml_row
from ai_mapping import at,bounded

PROMPT='''For each declared attack-story step compare the GT narrative to ONLY the supplied observed log records. Return {"items":[{"step_id":string,"state":"supported|partial|insufficient","citations":[{"record_id":string,"field":string,"value":any}],"missing_claims":[short Chinese strings],"reason":short Chinese string}]}.
Exactly one answer per input step. Cite an exact field path/value from supplied observed records, e.g. observed.operation or raw.CommandLine. Event/step IDs and label membership alone are not behavioral evidence. supported requires all material claims in the narrative to be evidenced; partial means some observable actions without enough proof for the full claim; insufficient means no adequate observation. Do not infer success, exploited CVEs, actual payload content, C2 intent, persistence execution, or exfiltrated file content solely from command invocation or port number. Missing source fields are not evidence of benignness. Do not invent citations. No numeric scores or chain-of-thought.'''

def prepare(root,normalized):
 inv=read(normalized/'01_inventory.json')['files'];steps={};scenario_by_step={}
 for s in inv:
  if s['role']!='ground_truth':continue
  for _,obj,loc,raw in records(root,s):
   scenario=obj.get('scenario_name',obj.get('scenario_id',s['path']))
   for st in obj.get('storyline_steps',obj.get('gt_steps',[])):
    if not isinstance(st,dict):continue
    uid=st.get('storyline_id',st.get('step_id',st.get('id')))
    if uid:
     if uid in steps and steps[uid]['GT']!=st:raise ValueError('Conflicting GT step ID across scenarios')
     steps[uid]={'step_id':uid,'scenario':scenario,'GT':st,'GT_source':{'file':s['path'],'sha256':s.get('sha256')},'evidence':[]};scenario_by_step[uid]=scenario
 kinds=defaultdict(set)
 for e in lines(normalized/'03_events.valid.jsonl.gz'):
  for sid in e.get('step_ids',[]):
   if sid not in steps:continue
   target=steps[sid]['evidence'];kind=e['native_type']
   if len(target)>=6 or kind in kinds[sid]:continue
   loc=e['provenance'];native={}
   if 'offset' in loc:
    p=(root/loc['file']).resolve()
    if not p.is_relative_to(root):raise ValueError('Evidence locator leaves input root')
    with p.open('rb') as f:f.seek(loc['offset']);raw=f.read(loc['length'])
    if hashlib.sha256(raw).hexdigest()!=loc['record_sha256']:raise ValueError('Evidence raw bytes changed')
    try:native=xml_row(raw) if raw.lstrip().startswith(b'<') else orjson.loads(raw)
    except (ValueError,TypeError):native={}
   target.append({'record_id':e['event_id'],'observed':{k:e[k] for k in ('event_time','subject_type','subject_id','operation','object_type','object_id','host','native_type','extensions')},'raw':bounded(native),'locator':loc})
   kinds[sid].add(kind)
 return list(steps.values())

def validate(answer,tasks):
 expected={t['step_id']:t for t in tasks};items=answer.get('items',[]);checks=[]
 if len(items)!=len(expected) or {x.get('step_id') for x in items}!=set(expected):raise ValueError('GT output step coverage mismatch')
 for x in items:
  t=expected[x['step_id']];ev={e['record_id']:e for e in t['evidence']};errors=[];state=x.get('state');citations=x.get('citations',[])
  if state not in ('supported','partial','insufficient'):errors.append('invalid state')
  if state in ('supported','partial') and not citations:errors.append('missing behavioral citations')
  for cite in citations:
   path=cite.get('field','');rid=cite.get('record_id')
   if rid not in ev or not path.startswith(('raw.','observed.')):errors.append('invalid evidence reference');continue
   value=at(ev[rid],path)
   if value is None or value!=cite.get('value'):errors.append('quote differs from supplied source field')
   if any(p.lower() in ('label','step_id','storyline_id','record_id','event_id') for p in path.split('.')):errors.append('annotation is not behavioral evidence')
  if state=='supported' and x.get('missing_claims'):errors.append('supported while admitting missing claims')
  if not t['evidence'] and state!='insufficient':errors.append('no input evidence')
  checks.append({**x,'valid_review':not errors,'validation_errors':errors,'final_state':state if not errors else 'unreviewed','scenario':t['scenario'],'evidence_records':len(ev)})
 return checks

def review(root,normalized,out,reviewer):
 tasks=prepare(root,normalized);save(out/'gt_evidence_packages.json',tasks);allchecks=[]
 if not tasks:
  result={'status':'GT_unavailable','value':None,'upper':1,'steps':[]};save(out/'gt_review.json',result);return result
 for start in range(0,len(tasks),4):
  batch=tasks[start:start+4]
  answer,d=reviewer.ask('gt_'+str(start//4+1),PROMPT,{'steps':batch},max_tokens=4500)
  try:checks=validate(answer,batch)
  except ValueError as exc:
   checks=[{'step_id':x['step_id'],'scenario':x['scenario'],'valid_review':False,'final_state':'unreviewed','validation_errors':[str(exc)]} for x in batch]
  save(d/'local_validation.json',checks);allchecks.extend(checks)
 # Reassess only claimed full support; keep the initial verdict and exact evidence.
 # This is a second semantic check, not independent proof of model correctness.
 save(out/'initial_reviews.json',allchecks)
 supported={c['step_id']:c for c in allchecks if c['final_state']=='supported'}
 audits=[]
 for t in tasks:
  if t['step_id'] not in supported:continue
  initial=supported[t['step_id']];cited={c['record_id'] for c in initial.get('citations',[])}
  audits.append({**t,'evidence':[e for e in t['evidence'] if e['record_id'] in cited],'initial_review':initial})
 for start in range(0,len(audits),4):
  batch=audits[start:start+4]
  instruction=PROMPT+' Audit the initial supported verdict skeptically. Explicitly check every material narrative qualifier: malware family identity cannot be inferred from an executable filename, command invocation does not prove successful completion, and an event does not prove a temporal sequence. Do not silently narrow the GT to its observable fragment. If any material qualifier lacks evidence, return partial and list it in missing_claims. A second model opinion is still uncertain, not a deterministic proof.'
  answer,d=reviewer.ask('gt_audit_'+str(start//4+1),instruction,{'steps':batch},max_tokens=3500)
  try:checks=validate(answer,batch)
  except ValueError as exc:checks=[{'step_id':x['step_id'],'scenario':x['scenario'],'valid_review':False,'final_state':'unreviewed','validation_errors':[str(exc)]} for x in batch]
  save(d/'local_validation.json',checks)
  updates={c['step_id']:c for c in checks}
  allchecks=[{**updates[c['step_id']],'initial_state':c['final_state'],'review_stage':'supported_claim_audit'} if c['step_id'] in updates else c for c in allchecks]
 per=[]
 for scenario in sorted({t['scenario'] for t in tasks}):
  rows=[c for c in allchecks if c['scenario']==scenario];counts=Counter(x['final_state'] for x in rows)
  per.append({'scenario':scenario,'steps':len(rows),'states':counts,'lower':counts['supported']/len(rows),'upper':(counts['supported']+counts['partial']+counts['unreviewed'])/len(rows)})
 result={'status':'reviewed' if all(x['valid_review'] for x in allchecks) else 'reviewed_with_rejected_outputs','value':sum(x['lower'] for x in per)/len(per),
  'upper':sum(x['upper'] for x in per)/len(per),'instances':per,'steps':allchecks,'scope':'AI narrative comparison of bounded, source-verified evidence; citations checked locally, semantic judgments not deterministic proof',
  'sampling':'up to 6 distinct native event types per step; unreviewed evidence can change conclusions'}
 save(out/'gt_review.json',result);return result
