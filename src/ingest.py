"""Fresh folder -> minimum-field events, join ledger, completeness report.

No historical result dependencies; raw input is read-only.
"""
from core import BASE,ROOT,RES,save,read,sha,stamp,emit,unwrap
from input_adapters import *
from event_contract import build,write_schema,present
from curves import technique_score
from technique_rules import evaluate
import argparse,fnmatch,sqlite3,sys,time

def protected(root,out):
 root=Path(root).resolve();out=Path(out).resolve()
 if not root.is_dir():raise ValueError('Input directory does not exist')
 if out.is_relative_to(root) or root.is_relative_to(out):raise ValueError('Output must be outside the input tree, and cannot contain the input tree')
 if out.exists() and any(out.iterdir()):raise ValueError('Output already contains files; choose a new run directory to preserve evidence')
 return root,out

def file_options(config,path):
 matches=[v for pat,v in config.get('files',{}).items() if fnmatch.fnmatchcase(path,pat)]
 if len(matches)>1:raise ValueError('Ambiguous file configuration: '+path)
 return matches[0] if matches else {}

def discover(root,config):
 inventory=[]
 for s in sources(root):
  if any(fnmatch.fnmatchcase(s['path'],p) for p in config.get('ignore',[])):
   inventory.append({**s,'role':'excluded','reason':'explicit config'});continue
  options=file_options(config,s['path'])
  try:p=probe(root,s)
  except (ValueError,OSError,KeyError,zipfile.BadZipFile) as exc:p={**s,'role':'unsupported','format':'unknown','reason':type(exc).__name__+': '+str(exc)}
  p.update({k:options[k] for k in ('role','format','schema','delimiter') if k in options})
  if options.get('fields') and options.get('role','data')=='data':p.update(role='data',schema='canonical')
  inventory.append(p)
 return inventory

def source_hash(root,s):
 h=hashlib.sha256()
 with open_source(root,s) as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()

def resolve_physical(root,reference,files,label_file=None):
 rel=str(reference).replace('\\','/')
 if Path(rel).is_absolute() or '..' in Path(rel).parts:raise ValueError('Unsafe GT source path')
 parent=Path(label_file).parent.as_posix() if label_file else '.'
 scoped=[p for p in files if p in ((parent+'/data/'+rel).lstrip('./'),(parent+'/'+rel).lstrip('./'))]
 possible=scoped or [p for p in files if p==rel or p=='data/'+rel]
 if len(possible)!=1:raise ValueError('GT physical source is absent or ambiguous: '+rel)
 return possible[0]

def label_indexes(root,inventory,config):
 physical=defaultdict(list);ids=defaultdict(list);node_ids=defaultdict(list);declared_instances=set();declared_steps=set();errors=[]
 paths={s['path'] for s in inventory};raw_labels=0
 for s in inventory:
  if s['role'] not in ('label','ground_truth'):continue
  if s.get('schema')=='aggregate_labels':continue # aggregate technique declarations are not event proof
  try:
   for index,row,loc,raw in records(root,s):
    fields=file_options(config,s['path']).get('fields')
    if fields:row={dest:row.get(src) for dest,src in fields.items()}
    if s['role']=='ground_truth':
     scenario=row.get('scenario_name') or row.get('scenario_id')
     steps=row.get('storyline_steps',row.get('gt_steps',[]))
     if scenario:declared_instances.add(str(scenario))
     for st in steps:
      sid=st.get('id',st.get('step_id',st.get('storyline_id'))) if isinstance(st,dict) else st
      if sid:declared_steps.add(str(sid))
     continue
    c=columns(row);raw_labels+=1;value=pick(c,'label','vertex_label','class');mapped=canon_label(value,config.get('label_map'))
    entry={'label':mapped,'label_raw':value,'label_file':s['path'],'label_row':index,
     'instance_id':pick(c,'instance_id','attack_chain','scenario_id'),'step_id':pick(c,'storyline_id','step_id'),'data_file':pick(c,'data_file','source_file')}
    if entry['instance_id']:declared_instances.add(str(entry['instance_id']))
    if entry['step_id']:declared_steps.add(str(entry['step_id']))
    if s.get('schema')=='physical_labels':
     path=resolve_physical(root,row['relative_path'],paths,s['path'])
     physical[path].append({**entry,'offset':int(row['byte_offset']),'length':int(row['byte_length']),
      'record_sha256':row['record_sha256'],'physical_id':row.get('physical_record_id'),'source_format':row.get('source_format')})
    else:
     uid=pick(c,'edge_uuid','event_uuid','record_id','uuid','flow_id')
     if uid is None:errors.append({'file':s['path'],'row':index,'reason':'missing label join key'});continue
     is_node='processname' in c and 'edgeuuid' not in c and 'eventuuid' not in c
     (node_ids if is_node else ids)[str(uid).strip().upper()].append({**entry,'host':pick(c,'host','host_id'),'scope':'node_context' if is_node else 'event'})
  except (ValueError,KeyError,TypeError) as exc:errors.append({'file':s['path'],'reason':str(exc)})
 return physical,ids,node_ids,declared_instances,declared_steps,raw_labels,errors

def physical_records(root,s,anchors,gaps):
 """Read declared byte ranges, verify them, and expose meaningful uncovered bytes."""
 seen=set();last=0
 with open_source(root,s) as f:
  for i,a in enumerate(sorted(anchors,key=lambda x:(x['offset'],x['length'])),1):
   anchor=(a['offset'],a['length'])
   if anchor in seen:continue
   seen.add(anchor)
   if a['offset']<last:raise ValueError('Overlapping GT byte ranges')
   gap=f.read(a['offset']-last)
   if gap.strip(b' \t\r\n[],') and not re.fullmatch(rb'\s*(<\?xml[^>]*>\s*)?(</?Events[^>]*>\s*)*',gap):
    gaps.append({'file':s['path'],'offset':last,'length':len(gap),'reason':'bytes outside physical GT; not silently treated as fully covered'})
   raw=f.read(a['length']);last=a['offset']+a['length']
   good=hashlib.sha256(raw).hexdigest()==a['record_sha256']
   fmt=a.get('source_format') or ''
   if raw.lstrip().startswith(b'<Event'):obj=xml_row(raw);kind='windows'
   elif raw.lstrip().startswith(b'{'):obj=orjson.loads(raw);kind=schema(obj)
   else:obj={'raw_text':raw.decode('utf-8','replace')};kind='opaque_text'
   yield i,obj,{'offset':a['offset'],'length':a['length']},raw,kind,good
  gap=f.read()
  if gap.strip(b' \t\r\n[],') and not re.fullmatch(rb'\s*(</?Events[^>]*>\s*)*',gap):gaps.append({'file':s['path'],'offset':last,'length':len(gap),'reason':'trailing bytes outside physical GT'})

def entities_for(root,files):
 """Fresh CDM entity declarations. Host namespace; no imported SQLite cache."""
 by=defaultdict(dict);count=0;conflicts=0;ambiguous=set()
 for s in files:
  for _,row,loc,raw in records(root,s):
   if 'datum' not in row:continue
   tag,o=next(iter(row['datum'].items()));kind=tag.rsplit('.',1)[-1]
   if kind=='Event':continue
   host=o.get('hostId',o.get('baseObject',{}).get('hostId',''));uid=o.get('uuid')
   if not uid:continue
   props=unwrap(o.get('properties')) or {};base=unwrap(o.get('baseObject',{}).get('properties')) or {}
   meta={'kind':kind,'path':props.get('path') if kind=='Subject' else base.get('filename')}
   if (host,uid) in ambiguous:continue
   if uid in by[host] and by[host][uid]['kind']!=kind:
    conflicts+=1;ambiguous.add((host,uid));del by[host][uid]
   elif uid in by[host] and by[host][uid]['path']!=meta['path']:by[host][uid]['path']=None
   else:by[host][uid]=meta
   count+=1
 return by,count,conflicts

def run(root,out,config=None,max_records=None,plan_only=False):
 root,out=protected(root,out);config=config or {};out.mkdir(parents=True)
 if max_records is not None and max_records<=0:raise ValueError('--max-records must be positive')
 for mapping in [config.get('label_map',{})]+[v.get('label_map',{}) for v in config.get('files',{}).values()]:
  if not set(mapping.values())<={'benign','malicious','contaminated','unknown'}:raise ValueError('label_map values must use canonical states')
 save(out/'run.json',{'stage':'discover','input':str(root),'started':stamp(),'python':sys.executable,'config':config,'historical_result_dependency':False,'external_calls':0})
 write_schema(out/'event.schema.json');inventory=discover(root,config)
 save(out/'01_inventory.json',{'root':str(root),'files':inventory,'scope':'bounded content probes; these are not full record statistics'})
 physical,labels,node_labels,instances,steps,label_rows,label_errors=label_indexes(root,inventory,config)
 for s in inventory:
  if s['path'] in physical:s.update(role='data',schema=s.get('schema','unknown'),physical_anchors=len(physical[s['path']]))
 data=[s for s in inventory if s['role']=='data'];unsupported=[s['path'] for s in inventory if s['role']=='unsupported']
 plan={'data_files':[s['path'] for s in data],'label_rows':label_rows,'event_label_keys':len(labels),'node_label_keys':len(node_labels),
  'physical_label_files':len(physical),'declared_instances':sorted(instances),'declared_steps':sorted(steps),'label_errors':label_errors,'unsupported_files':unsupported,
  'required_fields':['event_id','event_time','subject_type','subject_id','operation','object_type','object_id'],
  'config_example':{'files':{'custom.csv':{'role':'data','format':'csv','schema':'canonical','fields':{'timestamp':'time_column','source':'actor_column','source_type':'actor_type_column','operation':'action_column','target':'object_column','target_type':'object_type_column'},'time_unit':'ms','time_basis':'utc'}},'label_map':{'0':'benign','1':'malicious'}}}
 save(out/'02_input_plan.json',plan)
 if plan_only:
  save(out/'run.json',{'stage':'plan_only','input':str(root),'time':stamp(),'counts_are_not_full_scan':True});return plan
 if not data:raise ValueError('No recognized data files. Review 02_input_plan.json and provide --config; no score emitted.')
 # Hash current source bytes. Label/reference hashes are kept too when machine-readable.
 for s in inventory:
  if s['role'] in ('data','label','ground_truth'):s['sha256']=source_hash(root,s)
 save(out/'01_inventory.json',{'root':str(root),'files':inventory,'scope':'current source hashes; parsed record scope in summary.json'})
 cdm=[s for s in data if s.get('schema')=='cdm'];entities,entity_count,entity_conflicts=entities_for(root,cdm) if cdm else ({},0,0)
 db=sqlite3.connect(out/'identities.sqlite');db.execute('PRAGMA journal_mode=DELETE');db.execute('PRAGMA synchronous=NORMAL')
 db.execute('CREATE TABLE identity(key TEXT PRIMARY KEY,content_hash TEXT,label TEXT) WITHOUT ROWID')
 counts=Counter();native_types=Counter();label_counts=Counter();triples=Counter();missing=Counter();matched_labels=set();seen_instances=set();seen_steps=set();hits=[];errors=[];gaps=[];per_file=[]
 start=time.time();truncated=False
 with gzip.open(out/'03_events.valid.jsonl.gz','wb',compresslevel=1) as valid,gzip.open(out/'03_events.incomplete.jsonl.gz','wb',compresslevel=1) as incomplete,gzip.open(out/'04_label_joins.jsonl.gz','wb',compresslevel=1) as joins:
  for s in data:
   before=counts['records'];options=file_options(config,s['path']);anchors=physical.get(s['path']);anchor_map=defaultdict(list)
   for a in anchors or []:anchor_map[(a['offset'],a['length'])].append(a)
   try:
    stream=physical_records(root,s,anchors,gaps) if anchors else ((*x,s.get('schema','unknown'),True) for x in records(root,s))
    for index,row,loc,raw,kind,physical_good in stream:
     if kind=='cdm':
      tag,o=next(iter(row['datum'].items()))
      if not tag.endswith('.Event'):continue
      ent=entities.get(o.get('hostId',''),{})
     else:ent=None
     if max_records is not None and counts['records']>=max_records:truncated=True;break
     counts['records']+=1
     if options.get('record_regex') and 'raw_text' in row:
      match=re.search(options['record_regex'],row['raw_text'])
      row=match.groupdict() if match else row
     e=normalize(row,kind,s['path'],ent,options.get('fields'),options.get('constants'));e['adapter']=kind
     for dest,mapping in options.get('values',{}).items():
      if e.get(dest) is not None:e[dest]=mapping.get(str(e[dest]),e[dest])
     refs=[]
     if anchors:
      refs=anchor_map[(loc['offset'],loc['length'])] if physical_good else []
      if not physical_good:errors.append({'file':s['path'],**loc,'reason':'physical_GT_hash_mismatch'})
     else:
      for g in labels.get(str(e.get('native_id','')).strip().upper(),[]):
       scoped=g.get('host') or g.get('data_file') or len(data)==1
       globally_named_uuid=bool(re.fullmatch(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',str(e.get('native_id',''))))
       if not scoped and not globally_named_uuid:continue # avoid EventRecordID/row-number cross-file fanout
       if g.get('data_file') and g['data_file']!=s['path']:continue
       if not g.get('host') or str(g['host'])==str(e.get('host')):refs.append(g)
     embedded=canon_label(e.get('label_raw'),options.get('label_map',config.get('label_map')))
     values={g['label'] for g in refs if g['label']!='unknown'}
     if embedded!='unknown':values.add(embedded)
     e['label']='conflict' if len(values)>1 else next(iter(values),'unknown')
     if e['label']=='conflict':counts['label_conflicts']+=1
     e['label_evidence']=[{'file':g['label_file'],'row':g['label_row'],'label':g['label']} for g in refs]
     if embedded!='unknown':e['label_evidence'].append({'file':s['path'],'row':index,'basis':'embedded','label':embedded})
     e['instance_ids']=sorted({str(g['instance_id']) for g in refs if g.get('instance_id')} | ({str(e['instance_id'])} if e.get('instance_id') else set()))
     e['step_ids']=sorted({str(g['step_id']) for g in refs if g.get('step_id')} | ({str(e['step_id'])} if e.get('step_id') else set()))
     for g in refs:matched_labels.add((g['label_file'],g['label_row']))
     seen_instances.update(e['instance_ids']);seen_steps.update(e['step_ids'])
     record=build(e,{'file':s['path'],**loc,'record_sha256':hashlib.sha256(raw).hexdigest()},s['sha256'],options)
     record['native_format']=kind
     record['validation']['cause_scope']='unimplemented_format_mapping' if kind in ('unknown','opaque_text') else 'absent_source_value_or_unmapped_event_subtype; consult native_type and original byte anchor'
     # Unknown-node labels remain separate context, never event maliciousness.
     contexts=node_labels.get(str(e.get('source','')).upper(),[])
     if contexts:record['node_label_context']=contexts;counts['node_context_records']+=1
     content=hashlib.sha256(orjson.dumps(row,option=orjson.OPT_SORT_KEYS)).hexdigest()
     ident='native:'+json.dumps([e.get('host') or s['path'],e.get('identity_namespace',kind),e['native_id']]) if present(e.get('native_id')) else record['event_id']
     previous=db.execute('SELECT content_hash,label FROM identity WHERE key=?',(ident,)).fetchone()
     if previous:
      counts['duplicate_identity_records']+=1
      if previous[0]!=content:counts['identity_content_conflicts']+=1
      if previous[1]!=record['label']:counts['duplicate_label_conflicts']+=1
      record['duplicate_identity']=True
     else:
      db.execute('INSERT INTO identity VALUES(?,?,?)',(ident,content,record['label']));counts['unique_records']+=1
     native_types[str(e.get('native_type'))]+=1;label_counts[record['label']]+=1
     if record['validation']['valid']:
      counts['valid_records']+=1;emit(valid,record)
      if not previous:counts['valid_unique_records']+=1
      triples['|'.join((record['subject_type'],record['operation'],record['object_type']))]+=1
     else:
      counts['incomplete_records']+=1
      missing.update(x['field']+':'+x['reason'] for x in record['validation']['errors']);emit(incomplete,record)
     if refs or embedded!='unknown':emit(joins,{'event_id':record['event_id'],'provenance':record['provenance'],'label':record['label'],'references':record['label_evidence'],'instance_ids':record['instance_ids'],'step_ids':record['step_ids']})
     rh=evaluate({'record_id':record['event_id'],'label':record['label'],'operation':e.get('rule_operation',e.get('operation')),'command':e.get('command'),'target_path':e.get('target_path'),'gt_step':next(iter(e['step_ids']),None),'locator':record['provenance']})
     if not record['validation']['valid']:
      for h in rh:h['status']='input_incomplete_candidate';h['reason']='Seven-field input contract not satisfied; excluded from confirmed technique coverage'
     hits.extend(rh)
     if counts['records']%50000==0:
      db.commit();save(out/'progress.json',{'file':s['path'],'records':counts['records'],'valid':counts['valid_records'],'elapsed_seconds':round(time.time()-start)})
   except (ValueError,KeyError,TypeError,IndexError,struct.error,ET.ParseError,UnicodeError) as exc:errors.append({'file':s['path'],'reason':str(exc),'stage':'parse'})
   per_file.append({'path':s['path'],'records':counts['records']-before,'sha256':s['sha256']})
   if truncated:break
 db.commit();db.close()
 # Scenario GT may name one attack while its record GT only carries step IDs.
 if len(instances)==1 and not seen_instances and seen_steps & steps:seen_instances.update(instances)
 save(out/'05_rule_hits.json',hits)
 summary={'counts':counts,'labels':label_counts,'native_types':native_types,'triples':triples,'missing_fields':missing,'files':per_file,
  'label_rows':label_rows,'matched_label_rows':len(matched_labels),'unmatched_label_rows':label_rows-len(matched_labels),
  'declared_instances':sorted(instances),'observed_instances':sorted(seen_instances),'declared_steps':sorted(steps),'observed_steps':sorted(seen_steps),
  'errors':errors+label_errors,'physical_GT_uncovered_ranges':gaps,'unsupported_files':unsupported,'truncated':truncated,
  'CDM_entity_declarations':entity_count,'CDM_entity_conflicts':entity_conflicts,
  'complete_input_scan':not (truncated or errors or label_errors or gaps or unsupported or entity_conflicts),
  'identity_policy':'native identity within host/channel; otherwise physical location. Identical behavior is not automatically duplicate.',
  'C07_scope':'structural GT step linkage only; no claim of full narrative/semantic step support',
  'external_calls':0,'historical_result_dependency':False,'python':sys.executable,'elapsed_seconds':round(time.time()-start)}
 save(out/'summary.json',summary);result=score(summary,hits);save(out/'score.json',result)
 from input_checks import checks
 save(out/'06_checks.json',checks(summary))
 (out/'report.md').write_text(report(root,out,summary,result),encoding='utf-8')
 save(out/'run.json',{'stage':'complete' if summary['complete_input_scan'] else 'needs_review','input':str(root),'time':stamp(),'python':sys.executable,'config':config,'historical_result_dependency':False,'external_calls':0})
 return summary

def score(s,hits):
 c=s['counts'];n=c.get('records',0);u=c.get('unique_records',0);accepted=[h for h in hits if h['status']=='supported'];tech=sorted({h['parent_id'] for h in accepted});tactics=sorted({h['tactic_id'] for h in accepted})
 def metric(v,reason=None):return {'value':v,'status':'measured' if v is not None else 'unknown','reason':reason}
 universe={tuple(t) for t in read(RES/'input_triples.json')}
 observed={tuple(k.split('|')) for k in s['triples']};known=sum(s['labels'].get(k,0) for k in ('malicious','benign','contaminated'))
 m={'C01':metric(c.get('valid_unique_records',0)/n if n else None,'minimum-field valid unique records / physical events'),
 'C02':metric(len(set(s['observed_instances'])&set(s['declared_instances']))/len(s['declared_instances']) if s['declared_instances'] else None,'GT instance join coverage'),
 'C03':metric(known/n if n else None,'explicit label coverage on physical events; unknown not benign'),
 'C04':metric(min(len(tactics)/15,1),'confirmed tactics /15; detector dependent'),
 'C05':metric(technique_score(len(tech)),'1-(1-min(n,30)/30)^2'),
 'C06':metric(len(observed&universe)/len(universe),'valid node-operation-node combinations / frozen35'),
 'C07':metric(None,'GT linkage does not establish narrative semantics; requires independently defined step predicates')}
 if not s['complete_input_scan']:
  overall=None;status='incomplete_input_no_dataset_score'
 else:overall=100*sum(v['value'] or 0 for v in m.values())/7;status='confirmed_component_lower_bound'
 return {'protocol':'minimum-input-v1.0.0','metrics':m,'confirmed_component_lower_bound':overall,'status':status,
  'unknown_metrics':[k for k,v in m.items() if v['value'] is None],'confirmed_techniques':tech,'confirmed_tactics':tactics,
  'raw_technique_reference_ratio':len(tech)/192,'C05_saturation':30,'not_overall_quality':True,
  'missing_metrics_are_not_measured_zero':True}

def report(root,out,s,result):
 from reports import table,link
 text='# 统一输入与全面性报告 v1.0.0\n\n'
 text+=f"输入：`{root}`。本次从当前文件读取，无历史结果依赖、无外部模型调用。\n\n"
 text+='状态：'+('全量处理完成。' if s['complete_input_scan'] else '**输入尚未完全处理；不输出整个数据集的分数。**')+'\n\n'
 text+=table(['记录统计','数量'],s['counts'].items())
 text+='\n最小字段为 event_id、event_time、subject_type、subject_id、operation、object_type、object_id。必须全部有可解释的值，原始来源另行必填。缺字段的记录保留，未用占位词凑齐。\n\n'
 text+=table(['缺失/未映射字段','记录次数'],s['missing_fields'].items())
 text+='\n'+table(['标签状态','物理记录数'],s['labels'].items())
 text+=f"\n标签原始行 {s['label_rows']}，匹配行 {s['matched_label_rows']}，未匹配行 {s['unmatched_label_rows']}。节点标签只作为上下文，不扩散成事件恶意标签。\n\n"
 text+=table(['指标','值','定义/限制'],[[k,'0（当前证据不足）' if v['value'] is None else f"{100*v['value']:.4f}%",v['reason']] for k,v in result['metrics'].items()])
 text+='\n技术数 '+str(len(result['confirmed_techniques']))+'，技术评分采用 30 项饱和的递减斜率曲线。/192 仅保留为原始参考比例。C01 在新入口中衡量“满足最小字段的独立记录比例”，不同于旧报告仅核验身份的口径。\n\n'
 text+='GT 结构关联：声明 '+str(len(s['declared_steps']))+' 步，关联到 '+str(len(set(s['declared_steps'])&set(s['observed_steps'])))+' 步。这个数量不替代语义核验，C07 暂不强行给值。\n\n'
 text+='\n'+table(['原生类型','数量'],s['native_types'].items())+'\n'+table(['标准三元组','数量'],s['triples'].items())
 text+='\n未支持的文件：'+json.dumps(s['unsupported_files'],ensure_ascii=False)+'。解析/标签错误：'+str(len(s['errors']))+'；物理 GT 未覆盖字节区间：'+str(len(s['physical_GT_uncovered_ranges']))+'。详见 summary.json。\n\n'
 from input_checks import checks
 text+='\n'+table(['检验','状态','解释'],[[x['id']+' '+x['name'],x['status'],x['interpretation']] for x in checks(s)])
 text+='\n'.join(link(out/f) for f in ('event.schema.json','01_inventory.json','02_input_plan.json','03_events.valid.jsonl.gz','03_events.incomplete.jsonl.gz','04_label_joins.jsonl.gz','05_rule_hits.json','06_checks.json','summary.json','score.json'))+'\n'
 return text

def main(argv=None):
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path);p.add_argument('--config',type=Path);p.add_argument('--plan-only',action='store_true');p.add_argument('--max-records',type=int)
 a=p.parse_args(argv);out=a.output or BASE/'runs'/('input_'+datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f'))
 try:r=run(a.input,out,read(a.config) if a.config else {},a.max_records,a.plan_only)
 except Exception as exc:
  print(json.dumps({'error':str(exc),'type':type(exc).__name__},ensure_ascii=True));raise SystemExit(1)
 print(json.dumps({'output':str(out.resolve()),'records':r.get('counts',{}).get('records'),'complete':r.get('complete_input_scan'),'plan_only':a.plan_only},ensure_ascii=True))
 if not a.plan_only and not a.max_records and not r.get('complete_input_scan'):raise SystemExit(2)

if __name__=='__main__':main()
