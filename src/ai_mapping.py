"""AI proposes declarative mappings. A local compiler validates every proposal."""
from core import *
from ingest import discover
from input_adapters import records,normalize,path_value
from event_contract import TYPES,OPS,build
import itertools,re

NATIVE={'cdm','windows','ecar','etw','zdrz','flow','zeek','packet','standard','canonical','opaque_text'}
ROLES={'data','label','ground_truth','reference','container','unsupported'}
FIELDS={'native_id','record_id','timestamp','source','source_type','operation','target','target_type','command','target_path','host','label','instance_id','step_id'}

def at(obj,path):
 return path_value(obj,path)

def bounded(x,depth=0):
 if depth>4:return str(x)[:300]
 if isinstance(x,dict):return {k:bounded(v,depth+1) for k,v in list(x.items())[:40]}
 if isinstance(x,list):return [bounded(v,depth+1) for v in x[:3]]
 return x[:400] if isinstance(x,str) else x

def prepare(root,out):
 inventory=discover(root,{});profiles={};files=[]
 from defense_input import ensure_audit
 defense=ensure_audit(root,inventory,out/'defense')
 defense_files={x['path']:x for x in defense['files']}
 for i,s in enumerate(inventory):
  group=(s.get('format'),s.get('schema'),tuple(s.get('columns',[])))
  if group not in profiles:profiles[group]={'id':'P'+str(len(profiles)+1).zfill(3),'detected_role':s['role'],'format':s.get('format'),'schema':s.get('schema'),'files':[],'samples':[]}
  p=profiles[group];p['files'].append(s['path']);files.append({'id':'F'+str(i+1).zfill(3),'path':s['path'],'profile':p['id'],'bytes':s['bytes'],'detected_role':s['role']})
  if s['path'] in defense_files:files[-1]['defense_evidence']={'status':defense_files[s['path']]['status'],'categories':defense_files[s['path']]['categories']}
  if len(p['samples'])<3 and isinstance(s.get('sample'),dict):p['samples'].append({'id':p['id']+'S'+str(len(p['samples'])+1),'file':s['path'],'row':bounded(s['sample'])})
 payload={'profiles':list(profiles.values()),'files':files,'required_fields':['timestamp','source_type','source','operation','target_type','target'],'event_id':'generated from source hash and locator; native ID retained separately','native_adapters':sorted(NATIVE),'allowed_types':sorted(TYPES),'allowed_operations':sorted(OPS)}
 save(out/'directory_samples.json',payload);return inventory,payload

PROMPT='''Identify dataset file roles and field mappings. Return {"profiles":[{"id":exact profile ID,"role":"data|label|ground_truth|reference|container|unsupported","decision":"native|mapping|retain","schema":string,"fields":{canonical_field:"actual.path"},"constants":{},"values":{},"time_unit":null|"s"|"ms"|"us"|"ns","time_basis":null|"utc"|"relative"|"local_unspecified","evidence_ids":[sample IDs],"reason":Chinese short string}],"label_join_plan":string,"uncertainties":[string]}.
Return every profile exactly once. Prefer an already detected native adapter; do not replace its tested mapping with a partial generic mapping. A generic mapping may cite only fields actually present in sample rows. Constants allowed only source_type, target_type and operation with evidence of their meaning, never fabricated IDs, time or labels. If insufficient evidence retain unsupported. Do not treat metadata, aggregate labels, generated alerts or README as raw events. Reference files without samples may retain their detected roles without evidence IDs. No executable code, regex, commands or arbitrary paths. Do not decide whole-file maliciousness from filenames. The response is only a proposal; local validation controls execution.'''

def compile_plan(answer,payload):
 profiles={p['id']:p for p in payload['profiles']};items=answer.get('profiles',[]);errors=[];config={'files':{}};checks=[]
 if len(items)!=len(profiles) or {x.get('id') for x in items}!=set(profiles):return config,[{'error':'profile coverage mismatch'}],[]
 for item in items:
  p=profiles[item['id']];bad=[];samples={s['id']:s['row'] for s in p['samples']};eids=item.get('evidence_ids',[]);role=item.get('role');decision=item.get('decision');opt={}
  if role not in ROLES:bad.append('invalid role')
  if set(eids)-set(samples):bad.append('invented evidence ID')
  if p['detected_role']=='data' and role!='data':bad.append('cannot hide detected data as reference')
  if decision=='native':
   kind=item.get('schema')
   if kind!=p.get('schema') or kind not in NATIVE:bad.append('unverified native adapter change')
   if role!='data':bad.append('native adapter requires data role')
  elif decision=='mapping':
   if role!='data' or not samples or not eids:bad.append('mapping requires actual samples and data role')
   fields=item.get('fields',{});constants=item.get('constants',{});values=item.get('values',{})
   if set(fields)-FIELDS:bad.append('unsupported canonical field')
   for dest,path in fields.items():
    if not isinstance(path,str) or not any(at(row,path) is not None for row in samples.values()):bad.append('absent source field '+str(path))
   for field,value in constants.items():
    if field not in ('source_type','target_type','operation') or value not in (OPS if field=='operation' else TYPES):bad.append('forbidden constant '+field)
   if set(values)-FIELDS:bad.append('invalid enum mapping target')
   opt={'role':'data','format':p['format'],'fields':fields,'constants':constants,'values':values}
   for k,allowed in [('time_unit',('s','ms','us','ns')),('time_basis',('utc','relative','local_unspecified'))]:
    if item.get(k) is not None:
     if item[k] not in allowed:bad.append('invalid '+k)
     else:opt[k]=item[k]
  elif decision=='retain':
   if role!=p['detected_role']:bad.append('retain must preserve detected role')
  else:bad.append('invalid decision')
  if bad:errors.append({'profile':p['id'],'errors':bad})
  else:
   for path in p['files']:
    if opt:config['files'][path]=opt
  checks.append({'profile':p['id'],'accepted':not bad,'decision':decision,'role':role,'errors':bad,'evidence_ids':eids})
 return config,errors,checks

def trial(config,payload):
 results=[];errors=[]
 for p in payload['profiles']:
  for sample in p['samples']:
   opt=config['files'].get(sample['file'])
   if not opt:continue
   event=normalize(sample['row'],'canonical',sample['file'],mapping=opt['fields'],constants=opt.get('constants'));event['adapter']='canonical'
   for k,values in opt.get('values',{}).items():
    if event.get(k) is not None:event[k]=values.get(str(event[k]),event[k])
   r=build(event,{'file':sample['file'],'row':1},'0'*64,opt)
   results.append({'profile':p['id'],'sample':sample['id'],'valid':r['validation']['valid'],'errors':r['validation']['errors']})
 for pid in {r['profile'] for r in results}:
  if not any(r['valid'] for r in results if r['profile']==pid):errors.append({'profile':pid,'errors':['No sampled row meets the minimum-field contract with this mapping; retain unsupported if source fields are absent']})
 return results,errors

def propose(root,out,reviewer):
 inventory,payload=prepare(root,out);feedback=None
 for attempt in range(2):
  sent=payload if feedback is None else {**payload,'validation_errors_from_previous_attempt':feedback}
  answer,d=reviewer.ask('directory_'+str(attempt+1),PROMPT,sent,max_tokens=6500)
  config,errors,checks=compile_plan(answer,payload)
  trials,trial_errors=trial(config,payload) if not errors else ([],[]);errors+=trial_errors
  save(d/'local_validation.json',{'errors':errors,'checks':checks,'trial_conversion':trials})
  if not errors:
   save(out/'mapping_plan.json',answer);save(out/'validated_config.json',config);save(out/'mapping_validation.json',checks);return config
  feedback=errors
 raise ValueError('AI mapping failed local validation twice; proposals and feedback preserved')
