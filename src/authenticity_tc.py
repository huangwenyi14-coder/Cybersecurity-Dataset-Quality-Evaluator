"""Completed three-indicator authenticity protocol using user-selected DARPA TC reference."""
from core import *
import math,statistics,argparse

PROTOCOL='darpa-tc-authenticity-v1.0.0'
WEIGHTS={'annotation':.20,'time':.40,'behavior':.40}
POLICY={'time_scale_floors':{'log_mean_eps':math.log(10),'log_p95_eps':math.log(10),'log_burst_ratio':math.log(2),'zero_second_fraction':.20},
        'continuity_tolerance_floor':.05,'behavior_scale_floor':.15,'behavior_tolerance_floor':.02,
        'meaning':'Explicit engineering smoothness settings, not claimed empirical standard deviations. Rates use log1p; behavior units are proportions 0..1.'}


def fit(values,scale_floor,tolerance_floor=0):
 from authenticity import quantile
 if not values:raise ValueError('No baseline observations')
 median=statistics.median(values);mad=statistics.median(abs(x-median) for x in values)
 low=quantile(Counter(values),.1);high=quantile(Counter(values),.9)
 return {'center':median,'tolerance':max(median-low,high-median,tolerance_floor),'scale':max(2*1.4826*mad,scale_floor),
         'observations':len(values),'q10':low,'q90':high,'empirical_MAD':mad,'engineering_scale_floor':scale_floor,'engineering_tolerance_floor':tolerance_floor}


def compile_reference(statistics_path,output):
 from authenticity import checked_path
 path=checked_path(statistics_path);output=checked_path(output)
 if output.exists():raise ValueError('Do not overwrite a frozen reference')
 data=read(path)
 if data.get('kind')!='DARPA_TC_THEIA_full_stream' or not data['dedup_basis']['all_source_hashes_reverified_twice']:raise ValueError('Reference requires verified full THEIA stream')
 hours=[x for x in data['hourly'] if not x['boundary_partial'] and not x['empty_observed_hour']]
 if len(hours)<3:raise ValueError('Insufficient full observed hours')
 time_models={k:fit([h['time_features'][k] for h in hours],floor,POLICY['continuity_tolerance_floor'] if k=='zero_second_fraction' else 0)
              for k,floor in POLICY['time_scale_floors'].items()}
 behavior_hours=[h for h in hours if h['valid_records']]
 keys=sorted(data['behavior_counts']);models={k:fit([h['behavior_proportions'].get(k,0) for h in behavior_hours],POLICY['behavior_scale_floor'],POLICY['behavior_tolerance_floor']) for k in keys}
 mean={k:sum(h['behavior_proportions'].get(k,0) for h in behavior_hours)/len(behavior_hours) for k in keys}
 result={'protocol':PROTOCOL,'reference_name':'DARPA TC E3 THEIA','selection':'user requested DARPA TC as current real-data statistical reference',
         'source_statistics':str(path),'statistics_sha256':sha(path),'source_file_sha256':[x['sha256'] for x in data['source_files']],
         'source_counts':data['counts'],'reference_hours':[h['hour'] for h in hours],'time':time_models,'behavior':models,'behavior_mean':mean,
         'weights':WEIGHTS,'smoothness_policy':POLICY,'unseen_behavior':fit([0]*len(behavior_hours),POLICY['behavior_scale_floor'],POLICY['behavior_tolerance_floor']),
         'comparison_scope':'Similarity to this THEIA collection, across normalized sensor outputs as requested. Not probability of being real; acquisition differences can affect the score.',
         'hour_policy':'Nonempty full observed UTC hours; excludes first/last partial hour. Observation extent is not collection-uptime proof.',
         'created':stamp()}
 save(output,result)
 from reports import table,link
 text='# 数据集多指标质量评估系统：THEIA统计参考\n\n'
 text+='用户指定的当前真实数据统计参考；使用本地25个原始分片全量重算。\n\n'
 text+=table(['统计','值'],list(data['counts'].items())+[['拟合小时数',len(hours)],['行为种类',len(models)]])
 text+='\n'+table(['R02 时间特征','中心','容忍半宽','最终下降尺度','原始MAD','工程尺度下限'],[[k,m['center'],m['tolerance'],m['scale'],m['empirical_MAD'],m['engineering_scale_floor']] for k,m in time_models.items()])
 text+='\n参考时间特征是小时级统计；原始数据不需要服从正态分布。宽尺度下限是公开工程参数，不能解释为真实标准差。\n\n'
 text+=table(['行为','全量有效记录数','小时平均比例','比例中位数','容忍半宽','下降尺度'],[[k,data['behavior_counts'][k],mean[k],m['center'],m['tolerance'],m['scale']] for k,m in models.items()])
 text+='\n'+link(path,'全量统计及源哈希')+'\n'+link(path.parent/'second_counts.npz','每秒数组')+'\n'+link(path.parent/'normalized_samples.jsonl.gz','适配器交叉核验样本')+'\n'+link(output,'冻结评分参数')+'\n'
 output.with_suffix('.md').write_text(text,encoding='utf-8')
 return result


def annotation_score(annotation):
 counts=annotation.get('label_counts',{})
 assigned=annotation.get('assigned_label_records',sum(counts.get(k,0) for k in ('benign','malicious','contaminated','conflict')))
 review=annotation.get('semantic_review')
 if review is not None:
  from annotation_semantics import summarize
  result=summarize(review)
  if result['assigned']!=assigned:raise ValueError('Semantic review labeled population mismatch')
  return result
 return {'score':0.,'status':'no_explicit_event_labels' if not assigned else 'semantic_review_not_run',
         'assigned':assigned,'supported':0,'denominator':assigned,'selected_records':0,'reviewed_records':0,
         'total_steps':0,'reviewed_steps':0,'unit':'labeled_record','review_complete':False,
         'reason':'没有明确标签或尚未执行标注语义检查，R01记0分；来源可追溯仅作辅助统计，不再作为标注质量得分。'}


def score(profile,reference,annotation):
 from authenticity import gaussian,FEATURE_FAMILIES
 if reference.get('protocol')!=PROTOCOL:raise ValueError('Wrong DARPA reference protocol')
 ann=annotation_score(annotation or {})
 overlap=bool(set(profile.get('source_file_sha256',[]))&set(reference['source_file_sha256']))
 rows=[];time_sum=behavior_sum=0.;time_n=behavior_n=0
 for g in profile['groups']:
  r={'group':g['id'],'sensor':g['sensor'],'host':g['host'],'time_score':None,'behavior_score':None,
     'time_records':g['timed_records'],'behavior_records':g['valid_records'],'all_records':g['records'],
     'comparison_mode':'same-CDM-family' if g['sensor'].startswith('cdm/') else 'cross-sensor-DARPA-statistical-transfer',
     'time_features':{},'behavior_features':{}}
  for key,x in g['time_features'].items():
   m=reference['time'][key];s=gaussian(x,m['center'],m['tolerance'],m['scale'])
   r['time_features'][key]={'value':x,'reference':m,'score':s}
  family_values={}
  for family,keys in FEATURE_FAMILIES.items():
   vals=[r['time_features'][k]['score'] for k in keys if k in r['time_features']]
   if len(vals)==len(keys):family_values[family]=sum(vals)/len(vals)
  if len(family_values)==len(FEATURE_FAMILIES) and g['timed_records']:
   r['time_families']=family_values;r['time_score']=sum(family_values.values())/len(family_values)
   time_sum+=r['time_score']*g['timed_records'];time_n+=g['timed_records']
  p=g['behavior_proportions'];q=reference['behavior_mean'];contribution=0.;weights=0.
  if p:
   for key in sorted(set(p)|set(q)):
    m=reference['behavior'].get(key,reference['unseen_behavior']);weight=(p.get(key,0)+q.get(key,0))/2
    s=gaussian(p.get(key,0),m['center'],m['tolerance'],m['scale']);contribution+=weight*s;weights+=weight
    r['behavior_features'][key]={'proportion':p.get(key,0),'reference_mean':q.get(key,0),'reference':m,'weight':weight,'score':s,'reference_unseen':key not in reference['behavior']}
   if abs(weights-1)>1e-8:raise ValueError('Behavior distribution weights must sum to one')
   r['behavior_score']=contribution;behavior_sum+=contribution*g['valid_records'];behavior_n+=g['valid_records']
  rows.append(r)
 ts=time_sum/time_n if time_n else None;bs=behavior_sum/behavior_n if behavior_n else None
 weighted=reference['weights'];total=(weighted['annotation']*ann['score']+weighted['time']*ts+weighted['behavior']*bs) if all(x is not None for x in (ann['score'],ts,bs)) else None
 full=profile['input_complete'];n=profile['counters']['input_records']
 return {'protocol':PROTOCOL,'reference_name':reference['reference_name'],'status':'scored' if full and total is not None else 'preview_only' if not full else 'insufficient_normalized_fields',
         'annotation_score':ann['score'],'annotation_detail':ann,'annotation_protocol':'annotation-semantics-v1','time_score':ts if full else None,'behavior_score':bs if full else None,
         'authenticity_total':total if full else None,'preview_scores':None if full else {'annotation':ann['score'],'time':ts,'behavior':bs,'total':total},
         'input_complete':full,'weights':weighted,'groups':rows,'self_reference':overlap,
         'score_interpretation':'Self-reference descriptive score only, not independent validation.' if overlap else reference['comparison_scope'],
         'coverage':{'time_records':time_n,'behavior_records':behavior_n,'all_records':n,'time_fraction':time_n/n if n else 0,'behavior_fraction':behavior_n/n if n else 0},
         'scope':'Scores conditional on normalized records eligible for each feature. Mapping failures remain visible in coverage; no second completeness penalty.',
         'total_reason':'20% exhaustive step/annotation semantic support +40% time +40% behavior. Fixed engineering protocol, not an empirically validated universal authenticity probability.'}


def rescore(analysis,reference_path,output):
 """Upgrade existing feature outputs without replaying normalization or contacting a model."""
 from authenticity import checked_path,render
 analysis=checked_path(analysis);reference_path=checked_path(reference_path);output=checked_path(output)
 if output.exists():raise ValueError('Use a new rescoring directory')
 p=read(analysis/'features.json');annotation=read(analysis/'annotation_profile.json');ref=read(reference_path)
 # Recount event evidence from the existing normalized files: reference counts alone are ambiguous.
 norm=checked_path(p['normalized']);assigned=traced=0
 for file in ('03_events.valid.jsonl.gz','03_events.incomplete.jsonl.gz'):
  if sha(norm/file)!=p['input_sha256'][file]:raise ValueError('Normalized input changed')
  for e in lines(norm/file):
   label=e.get('label')
   if label not in ('benign','malicious','contaminated','conflict'):continue
   assigned+=1
   if label!='conflict' and any(r.get('label')==label and r.get('file') and isinstance(r.get('row'),int) and r['row']>0 for r in e.get('label_evidence',[])):
    traced+=1
 annotation['assigned_label_records']=assigned;annotation['event_level_traceable_labels']=traced
 annotation.pop('semantic_review',None) # Offline rescoring never reuses unbound semantic conclusions.
 s=score(p,ref,annotation);output.mkdir(parents=True)
 save(output/'authenticity_scores.json',s);save(output/'annotation_profile.json',annotation);save(output/'reference_profile.json',ref)
 # Link to preserved primary statistics; do not copy the potentially large observations database.
 from reports import table,link
 def val(x):return '输入不足/仅预览' if x is None else f'{x:.4f}'
 from metric_catalog import VERSION as system_version
 text='# 真实性评分 '+system_version+' — DARPA TC 参考\n\n'
 text+=f"**真实性：{val(s['authenticity_total'])}/100。**\n\n"
 text+=table(['一级','二级','三级','单项分/100','权重'],[['真实性','标注质量','R01 标注语义支持',val(s['annotation_score']),'20%'],['真实性','数据真实度','R02 时间特征',val(s['time_score']),'40%'],['真实性','数据真实度','R03 行为分布',val(s['behavior_score']),'40%']])
 text+='\n参考为用户指定的 DARPA TC E3 THEIA。此分数表示本协议下的规范化统计相似度与标注语义支持，不是真实来源概率；跨采集器差异可能影响分数。\n\n'
 text+=table(['参与范围','记录数','占原始记录比例'],[['时间',s['coverage']['time_records'],f"{s['coverage']['time_fraction']:.2%}"],['行为',s['coverage']['behavior_records'],f"{s['coverage']['behavior_fraction']:.2%}"]])
 text+=f"\n辅助统计：明确标签 {assigned:,} 条，其中事件级证据可追溯 {traced:,} 条。本离线重算不执行语义检查，R01为0；可追溯数量不用于R01计分。\n\n"
 if s['preview_scores']:text+='输入仅为预览，条件分项供调试，不作为全量数据集分数：`'+json.dumps(s['preview_scores'])+'`。\n\n'
 text+=table(['分组','日志类型','时间分','行为分','时间记录','行为记录'],[[g['group'],g['sensor'],val(g['time_score']),val(g['behavior_score']),g['time_records'],g['behavior_records']] for g in s['groups']])
 text+='\n疑似断档仍只是候选，不额外扣分；连续性通过零事件秒比例与参考曲线比较。未知行为使用显式宽曲线而不被忽略。各参数、代入值、逐组分数均保存在评分JSON。\n\n'
 text+='\n'.join([link(analysis/'report.md','原始时间、行为分布与疑似断档报告'),link(output/'authenticity_scores.json','全部计算明细'),link(output/'reference_profile.json','冻结DARPA参考参数')])+'\n'
 (output/'report.md').write_text(text,encoding='utf-8')
 save(output/'verification.json',{'source_analysis':str(analysis),'features_sha256':sha(analysis/'features.json'),'reference_sha256':sha(reference_path),
      'annotation_recounted':True,'weights_sum_one':abs(sum(s['weights'].values())-1)<1e-12,'total_formula':s['authenticity_total'] is None or abs(s['authenticity_total']-(.2*s['annotation_score']+.4*s['time_score']+.4*s['behavior_score']))<1e-8,'external_calls':0,'time':stamp()})
 return s


if __name__=='__main__':
 p=argparse.ArgumentParser();sub=p.add_subparsers(dest='command',required=True)
 a=sub.add_parser('compile');a.add_argument('--statistics',required=True,type=Path);a.add_argument('--output',required=True,type=Path)
 a=sub.add_parser('rescore');a.add_argument('--analysis',required=True,type=Path);a.add_argument('--reference',required=True,type=Path);a.add_argument('--output',required=True,type=Path)
 a=p.parse_args()
 if a.command=='compile':r=compile_reference(a.statistics,a.output);print(json.dumps({'hours':len(r['reference_hours']),'behavior_types':len(r['behavior'])}))
 else:r=rescore(a.analysis,a.reference,a.output);print(json.dumps({k:r[k] for k in ('annotation_score','time_score','behavior_score','authenticity_total','status')}))
