"""Seven required semantic fields plus verifiable provenance. No dummy filling."""
from core import *
from decimal import Decimal,InvalidOperation
import re

FIELDS=('event_id','event_time','subject_type','subject_id','operation','object_type','object_id')
TYPES={'process','file','network_endpoint','memory','account','host','registry','module','thread','session','domain','command','pipe','service','device'}
OPS={'spawn','execute','terminate','access','open','create','read','write','delete','rename','change_permissions','change_owner','modify_attributes','load','map','unmap','protect','share_memory','connect','send','receive','read_socket_parameters','write_socket_parameters','modify','query','login','logout','communicate','create_remote'}
EMPTY={'','unknown','null','none','nan','n/a','na','-','?','00000000-0000-0000-0000-000000000000'}
OPS.update({'block','isolate','quarantine','disable'}) # Typed observed actions; defense intent still requires separate evidence.

def present(value):return value is not None and str(value).strip().lower() not in EMPTY

def event_time(value,unit=None,basis=None):
 if not present(value):return None
 if isinstance(value,dict):
  if value.get('basis') not in ('utc','local_unspecified','relative') or not present(value.get('value')):return None
  # Revalidate rather than trusting a nonempty object.
  return event_time(value['value'],value.get('unit'),value.get('basis'))
 s=str(value).strip()
 if re.fullmatch(r'[+-]?\d+(\.\d+)?',s):
  if unit not in ('s','ms','us','ns'):return None
  try:n=Decimal(s)
  except InvalidOperation:return None
  if not n.is_finite():return None
  return {'value':s,'unit':unit,'basis':basis or 'utc'}
 try:
  # Python 3.9 rejects seven-digit Windows fractional seconds; retain raw precision.
  parseable=re.sub(r'\.(\d+)',lambda m:'.'+(m.group(1)+'000000')[:6],s)
  d=datetime.datetime.fromisoformat(parseable.replace('Z','+00:00'))
 except ValueError:return None
 if d.tzinfo:return {'value':d.astimezone(datetime.timezone.utc).isoformat(),'unit':'iso8601','basis':'utc','raw':s}
 return {'value':d.isoformat(),'unit':'iso8601','basis':'local_unspecified','raw':s}

def build(event,locator,source_sha256,config=None):
 config=config or {};kind=event.get('adapter');timestamp=event.get('timestamp')
 default_units={'cdm':('ns','utc'),'packet':('s','utc'),'etw':('ms','relative'),'zeek':('s','utc'),'ecar':('ms','utc')}
 unit,basis=default_units.get(kind,(None,None));unit=config.get('time_unit',unit);basis=config.get('time_basis',basis)
 physical=hashlib.sha256((source_sha256+'|'+json.dumps(locator,sort_keys=True)).encode()).hexdigest()
 record={
  'event_id':'physical:'+physical,'event_time':event_time(timestamp,unit,basis),
  'subject_type':event.get('source_type'),'subject_id':str(event['source']) if event.get('source') is not None else None,
  'operation':event.get('operation'),'object_type':event.get('target_type'),'object_id':str(event['target']) if event.get('target') is not None else None,
  'provenance':{'source_sha256':source_sha256,**locator},
  'native_id':event.get('native_id'),'native_type':event.get('native_type'),'host':event.get('host'),
  'label':event.get('label','unknown'),'label_raw':event.get('label_raw'),'label_evidence':event.get('label_evidence',[]),
  'instance_ids':event.get('instance_ids',[]),'step_ids':event.get('step_ids',[]),
  'extensions':{k:event[k] for k in ('command','target_path','rule_operation','src_ip','dst_ip','src_port','dst_port','protocol','mapping_caveat','captured_bytes','wire_bytes','tcp_flags') if event.get(k) is not None}}
 errors=validate(record)
 record['validation']={'valid':not errors,'errors':errors}
 return record

def validate(record):
 errors=[]
 for name in FIELDS:
  if not present(record.get(name)):errors.append({'field':name,'reason':'missing_or_placeholder'})
 if record.get('event_time') is not None and not event_time(record['event_time']):errors.append({'field':'event_time','reason':'unparseable_or_unspecified_numeric_unit'})
 for name in ('subject_type','object_type'):
  if present(record.get(name)) and record[name] not in TYPES:errors.append({'field':name,'reason':'unmapped_node_type'})
 if present(record.get('operation')) and record['operation'] not in OPS:errors.append({'field':'operation','reason':'unmapped_operation'})
 p=record.get('provenance',{})
 if not p.get('file') or not p.get('source_sha256') or not any(k in p for k in ('offset','row','packet')):errors.append({'field':'provenance','reason':'missing_original_location'})
 return errors

def write_schema(path):
 props={n:{'type':'string','minLength':1} for n in FIELDS if n!='event_time'}
 props.update(subject_type={'enum':sorted(TYPES)},object_type={'enum':sorted(TYPES)},operation={'enum':sorted(OPS)},
  event_time={'type':'object','required':['value','unit','basis'],'properties':{'value':{'type':'string','minLength':1},'unit':{'enum':['s','ms','us','ns','iso8601']},'basis':{'enum':['utc','relative','local_unspecified']}}},
  provenance={'type':'object','required':['file','source_sha256'],'properties':{'file':{'type':'string','minLength':1},'source_sha256':{'type':'string','pattern':'^[0-9a-f]{64}$'}},'anyOf':[{'required':['offset']},{'required':['row']},{'required':['packet']}]})
 save(path,{'$schema':'https://json-schema.org/draft/2020-12/schema','title':'Security event minimum contract v1.0.0','type':'object','required':list(FIELDS)+['provenance'],'properties':props,
  '$comment':'The runtime additionally rejects placeholder strings and checks timestamp interpretation; schema alone does not establish evidence provenance.'})
