"""Discover defense evidence separately from raw events; never infer executed defenses from alerts."""
from core import *
from input_adapters import records,open_source
import re,argparse

def categories(row):
 if not isinstance(row,dict):return []
 found=[];typ=str(row.get('event_type','')).lower()
 if ('alert_id' in row and ('alert' in row or 'alert_reason' in row)) or typ=='alert':found.append('alert')
 if ('action_id' in row and 'action_type' in row) or typ in ('defense_action','response_action'):found.append('action_declaration')
 if ('policy_id' in row or 'rule_id' in row) and any(k in row for k in ('configuration','rules','policy')):found.append('policy')
 if ('action_id' in row and any(k in row for k in ('result_status','outcome','result'))) or typ=='defense_result':found.append('result_declaration')
 return found

def candidate(s):
 kinds=categories(s.get('sample'))
 if s.get('schema')=='derived_alerts' and 'alert' not in kinds:kinds.append('alert')
 hint=bool(re.search(r'(^|[/_.-])(defen[cs]e|alerts?|response|mitigations?|firewall|edr|ids|ips)([/_.-]|$)',s['path'],re.I))
 return {'path':s['path'],'original_role':s.get('role'),'format':s.get('format'),'schema':s.get('schema'),
         'categories':kinds,'basis':'sample_content' if kinds else 'path_hint_only',
         'status':'identified' if kinds else 'candidate_needs_adapter'} if kinds or hint else None

def ensure_audit(root,inventory,out):
 """Resume only with unchanged defense sources, labels and cited original files."""
 from ingest import source_hash
 out=Path(out);root=Path(root).resolve()
 if not (out/'inventory.json').exists():return audit(root,inventory,out)
 previous=read(out/'inventory.json');sources={s['path']:s for s in inventory}
 if Path(previous['root']).resolve()!=root or {s['path'] for s in inventory if candidate(s)}!={s['path'] for s in previous['files']}:raise ValueError('Defense input scope changed; use a fresh run')
 hashes={x['path']:x['source_sha256'] for x in previous['files'] if x.get('source_sha256')}
 hashes.update({x['file']:x['sha256'] for x in previous['label_sources']})
 for item in lines(out/'evidence.jsonl.gz'):
  link=item['log_link']
  if link.get('source_sha256'):hashes[link['file']]=link['source_sha256']
 for path,digest in hashes.items():
  if path not in sources or source_hash(root,sources[path])!=digest:raise ValueError('Defense audit source changed: '+path)
 return previous

def audit(root,inventory,out,max_records=None):
 from ingest import source_hash,resolve_physical
 from reports import table,link
 root=Path(root).resolve();out=Path(out).resolve()
 if out.is_relative_to(root) or root.is_relative_to(out):raise ValueError('Unsafe defense audit paths')
 if out.exists() and any(out.iterdir()):raise ValueError('Preserve prior defense audit; use a fresh output')
 out.mkdir(parents=True,exist_ok=True);files=[];items=[];errors=[];all_sources={s['path']:s for s in inventory}
 for source in inventory:
  c=candidate(source)
  if not c:continue
  files.append(c);c['records_scanned']=0;c['category_counts']={};c['complete_scan']=False
  if source.get('format') not in ('json','csv','xml'):
   c['reason']='Candidate needs a supported structural adapter; not evidence of absence';continue
  try:
   digest=source_hash(root,source);c['source_sha256']=digest;counts=Counter();declared=0;unclassified=0
   for i,row,loc,raw in records(root,source):
    if max_records is not None and c['records_scanned']>=max_records:
     c['status']='partial_scan';c['reason']='Safety limit reached; remaining rows unreviewed';break
    c['records_scanned']+=1;kinds=categories(row)
    if not kinds:unclassified+=1;continue
    counts.update(kinds);declared+=1
    if not isinstance(row,dict):continue
    items.append({'file':source['path'],'row':i,'categories':kinds,
      'provenance':{'file':source['path'],'source_sha256':digest,**loc,'record_sha256':hashlib.sha256(raw).hexdigest()},
      'alert_id':row.get('alert_id'),'alert':row.get('alert'),'confidence_score':row.get('confidence_score'),
      'alert_reason':row.get('alert_reason'),'location':row.get('location'),
      'declared_defense':{k:row[k] for k in ('action_id','action_type','action','execution_status','executed','result_status','result','outcome','mitigation_id','policy_id','rule_id','target','timestamp','host','execution_event_ids','result_event_ids') if k in row},
      'semantic_status':'source_declaration_only_not_verified_execution','log_link':{'status':'no_supported_locator'}})
   else:c['complete_scan']=True
   c.update(category_counts=dict(counts),evidence_records=declared,unclassified_records=unclassified)
   if counts and c['status']!='partial_scan':c['status']='identified';c['categories']=sorted(counts);c['basis']='full_record_content'
   if not counts:c['reason']='No recognized defense schema in scanned records; does not prove no defense data'
   if source_hash(root,source)!=digest:raise ValueError('Defense source changed during audit')
  except (ValueError,KeyError,TypeError,OSError,IndexError) as exc:
   c['status']='parse_failed';c['complete_scan']=False;errors.append({'file':source['path'],'error':str(exc)})
 requested={x['location'].get('physical_record_id') for x in items if isinstance(x.get('location'),dict)}-{None}
 anchors=defaultdict(list);label_sources=[]
 if requested:
  for source in inventory:
   if source.get('schema')!='physical_labels':continue
   digest=source_hash(root,source);label_sources.append({'file':source['path'],'sha256':digest})
   try:
    for i,row,loc,raw in records(root,source):
     if row.get('physical_record_id') in requested:anchors[row['physical_record_id']].append((source['path'],i,row))
    if source_hash(root,source)!=digest:raise ValueError('Label source changed during audit')
   except (ValueError,OSError,KeyError,TypeError) as exc:errors.append({'file':source['path'],'error':str(exc)})
 linked=Counter();target_hashes={}
 for item in items:
  loc=item.get('location');uid=loc.get('physical_record_id') if isinstance(loc,dict) else None
  if not uid:continue
  matches=anchors[uid]
  if len(matches)!=1:item['log_link']={'status':'missing_anchor' if not matches else 'ambiguous_anchor','candidates':len(matches)};continue
  label_file,label_row,a=matches[0]
  try:
   path=resolve_physical(root,a['relative_path'],all_sources,label_file)
   if loc.get('relative_path')!=a['relative_path'] or ('record_index' in loc and loc['record_index']!=a.get('record_index')):raise ValueError('Alert locator conflicts with physical GT anchor')
   off=int(a['byte_offset']);size=int(a['byte_length'])
   if off<0 or size<1 or size>64*1024**2:raise ValueError('Invalid source byte range')
   with open_source(root,all_sources[path]) as f:f.seek(off);raw=f.read(size)
   if len(raw)!=size or hashlib.sha256(raw).hexdigest()!=a['record_sha256']:raise ValueError('Original record hash mismatch')
   if path not in target_hashes:target_hashes[path]=source_hash(root,all_sources[path])
   item['log_link']={'status':'verified_physical_record','physical_record_id':uid,'file':path,'offset':off,'length':size,
     'record_sha256':a['record_sha256'],'source_sha256':target_hashes[path],'label_file':label_file,'label_row':label_row,
     'label':a.get('label','unknown'),'timestamp_matches_GT_text':loc.get('timestamp')==a.get('observed_time'),
     'scope':'Verifies cited record identity, not alert correctness or defense execution'}
   linked[a.get('label','unknown')]+=1
  except (ValueError,KeyError,TypeError,OSError) as exc:item['log_link']={'status':'verification_failed','reason':str(exc)}
 counts=Counter(k for item in items for k in item['categories']);links=Counter(x['log_link']['status'] for x in items)
 result={'protocol':'defense-input-v1.0.0','root':str(root),'time':stamp(),'files':files,
   'status':'identified' if items else 'candidates_unresolved' if files else 'not_identified_by_current_detector',
   'counts':dict(counts),'evidence_records':len(items),'link_counts':dict(links),'linked_record_labels':dict(linked),
   'alert_types':dict(Counter(x['alert'] for x in items if isinstance(x.get('alert'),str))),
   'complete_selected_file_scan':all(x['complete_scan'] for x in files),'label_sources':label_sources,'errors':errors,
   'defense_verification_state':'pending_execution_and_outcome_verification' if counts['action_declaration'] or counts['result_declaration'] else 'insufficient_execution_and_outcome_evidence',
   'scope':'Candidate discovery is schema/sample based, not proof of absence across arbitrary logs. Alerts and policies do not prove actions were executed.',
   'external_calls':0}
 save(out/'inventory.json',result)
 with gzip.open(out/'evidence.jsonl.gz','wb') as f:
  for item in items:emit(f,item)
 text='# 防御材料识别与处理\n\n输入目录：`'+str(root)+'`。\n\n'
 text+='目录阶段单独列出防御材料，保留原始事件/标签等主角色，不把告警重复计入原始日志数量。路径提示只是候选；内容识别、全文件解析及日志定位核验分开记录。\n\n'
 text+=table(['对应文件','分类','状态','读取记录','解析完整'],[[x['path'],', '.join(x.get('categories',[])) or '待确认',x['status'],x['records_scanned'],x['complete_scan']] for x in files])
 text+='\n'+table(['统计','数量'],list(counts.items())+[['原始定位：'+k,v] for k,v in links.items()]+[['所引用记录GT标签：'+k,v] for k,v in linked.items()])
 text+='\n'+table(['告警类型','条数'],list(result['alert_types'].items()))
 text+='\n'+table(['证据ID','文件/记录序号','类别','原始日志','定位核验','引用记录标签'],[[x['alert_id'] or x['declared_defense'].get('action_id','未提供'),x['file']+':'+str(x['row']),','.join(x['categories']),x['log_link'].get('file',''),x['log_link']['status'],x['log_link'].get('label','')] for x in items[:200]])
 text+='\n只在报告中展示前200条，全部结构化记录见证据文件。定位匹配不等于告警语义正确，也不证明实施过阻断、隔离或其他缓解措施；来源中的置信度和模型描述只作原文声明保存。引用记录被GT标为良性，不能单凭此认定聚合告警误报。\n\n'
 text+='A03/A04状态：`'+result['defense_verification_state']+'`。未做模型语义审查、未发布对抗性分数。没有识别到支持的格式时不能声称数据集没有防御材料。\n\n'
 text+=link(out/'inventory.json','完整目录与统计')+'\n'+link(out/'evidence.jsonl.gz','逐条特征、来源与原始定位核验')+'\n'
 (out/'report.md').write_text(text,encoding='utf-8');return result

if __name__=='__main__':
 from ingest import protected,discover
 p=argparse.ArgumentParser();p.add_argument('--input',required=True,type=Path);p.add_argument('--output',required=True,type=Path);a=p.parse_args()
 root,out=protected(a.input,a.output);r=audit(root,discover(root,{}),out)
 print(json.dumps({k:r[k] for k in ('status','counts','link_counts','linked_record_labels','defense_verification_state')},ensure_ascii=True))
