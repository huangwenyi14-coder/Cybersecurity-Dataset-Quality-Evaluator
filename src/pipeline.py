"""Cybersecurity-Dataset-Quality-Evaluator: folder to auditable multidimensional quality report."""
from core import *
from ingest import protected,run as ingest_run
from archive_input import materialize
from ai_transport import Reviewer
from ai_mapping import propose,prepare
from ai_steps import review as review_steps
import argparse,sys
from metric_catalog import VERSION, SYSTEM_NAME

def finalize(out,ai_gt):
 data=out/'normalized';result=read(data/'score.json');summary=read(data/'summary.json')
 result['protocol']='completeness-v1.0.0';result['metrics']['C07']={'value':ai_gt.get('value'),'upper':ai_gt.get('upper',1),'status':ai_gt['status'],'reason':'GT narrative compared with source-verified logs; model citations validated'}
 values=result['metrics'];result['unknown_metrics']=[k for k,v in values.items() if v['value'] is None]
 complete=summary['complete_input_scan']
 result['score']=sum((m['value'] or 0)*100/7 for m in values.values()) if complete else None
 result['upper_score']=sum((1 if m['value'] is None or k in ('C04','C05') else m.get('upper',m['value']))*100/7 for k,m in values.items()) if complete else None
 result['score_semantics']='equal-weight confirmed-evidence lower score /100; unknown or unrecognized techniques are not proven absent'
 result['upper_score_semantics']='optimistic scenario under this bounded-evidence protocol; not a mathematical upper bound on actual dataset quality or a statistical confidence interval'
 result['all_seven_have_values']=not result['unknown_metrics'];result['input_complete']=complete;result['status']='scored' if complete else 'input_incomplete_no_global_score'
 result['confirmed_component_lower_bound']=result['score'];save(out/'score.json',result)
 from reports import table,link,NAMES
 text='# 全面性评分报告 v1.0.0\n\n'
 state=read(out/'workflow.json');text+='输入目录：`'+state['original_input']+'`。\n\n'
 text+=f"**全面性证据分：{result['score']:.2f}/100；当前证据协议的乐观情形：{result['upper_score']:.2f}/100。**\n\n" if complete else '**输入尚未完整处理，未输出整个数据集的分数。**\n\n'
 text+='分值来自固定等权协议；缺少可确认材料按0分贡献，证据分不代表穷尽识别能力，也不是统计置信区间。乐观情形只按本次证据和未确定项计算，不是数据集真实质量的数学上界。仅评价全面性。\n\n'
 text+='流程：目录/压缩包清单 → AI 格式判断 → 映射字段验证与试转换 → 全量七字段转换 → 标签关联 → 技术规则与三元组统计 → GT 步骤模型核验及引用检查 → 固定公式。\n\n'
 formulas={'C01':'七字段完整且身份独立的记录数 / 原始事件数','C02':'有日志关联的 GT 实例数 / 声明实例数','C03':'明确恶意或良性记录数 / 原始事件数','C04':'日志规则确认的战术数 /15','C05':'1−(1−min(父技术数,30)/30)²','C06':'完整记录命中的参考三元组种类 /35','C07':'各实例完整支持步骤比例的平均值（模型判断，引用本地校验）'}
 text+=table(['一级','二级','三级指标','指标值','加权贡献','计算方式'],[['全面性','规模与可用性' if k in ('C01','C02','C03') else '覆盖范围' if k in ('C04','C05','C06') else '攻击过程',k+' '+NAMES[k],f"{v['value']*100:.4f}%" if v['value'] is not None else '0（证据不足）',f"{v['value']*100/7:.4f}" if v['value'] is not None else '0',formulas[k]] for k,v in values.items()])
 text+='\n'+table(['原始统计','值'],list(summary['counts'].items())+[['标签：'+k,v] for k,v in summary['labels'].items()]+[['GT实例数',len(summary['declared_instances'])],['GT步骤数',len(summary['declared_steps'])],['战术数',len(result['confirmed_tactics'])],['父技术数',len(result['confirmed_techniques'])],['标准三元组种类',len(summary['triples'])]])
 text+='\nC05 使用 `100 × [1 − (1 − min(父技术数,30)/30)²]`，30 项满分。字段不完整记录的技术命中只保留为候选；没有标签的记录不自动当良性。\n\n'
 text+='确认父技术：'+', '.join(result['confirmed_techniques'])+'；确认战术：'+', '.join(result['confirmed_tactics'])+'。这些是当前规则识别结果，不代表穷尽数据集所有技术。\n\n'
 text+=f"标签原始行 {summary['label_rows']:,}；匹配 {summary['matched_label_rows']:,}；未匹配 {summary['unmatched_label_rows']:,}。逐记录来源与连接证据见 normalized/04_label_joins.jsonl.gz；C02/C03 不衡量标签正确性或样本数量是否充足。\n\n"
 text+='C07 每个 GT 实例内部计算完整支持步骤占比，再对实例等权。部分支持进入乐观情形、不进入确认分。模型回复必须引用本次提供的实际字段和值；引用错或自相矛盾的回复标为未核验。完整支持项另做一次限定声明复核，初次判断保存在 initial_reviews.json。每步最多提供 6 个不同原生事件类型样本，因此结论受证据选择影响；两次模型语义判断也不是确定性证明。\n\n'
 if ai_gt.get('steps'):text+=table(['GT步骤','模型判断','最终状态','引用检查','缺少证据的声明'],[[r['step_id'],r.get('state','未返回'),r['final_state'],'通过' if r['valid_review'] else str(r['validation_errors']),'; '.join(r.get('missing_claims',[]))] for r in ai_gt['steps']])
 usage=read(out/'ai/usage.json') if (out/'ai/usage.json').exists() else {'calls':[],'usage':{}}
 text+=f"\nAI 调用 {len(usage['calls'])} 次；输入 token {usage['usage'].get('prompt_tokens',0):,}；输出 token {usage['usage'].get('completion_tokens',0):,}。仅发送已保存的格式样本和 GT 核验证据包，不发送全量日志。\n\n"
 text+='\n'.join(link(out/f,title) for f,title in [('mapping/directory_samples.json','目录样本'),('mapping/validated_config.json','实际执行的映射'),('mapping/mapping_validation.json','映射验证'),('normalized/report.md','逐项输入与标签统计'),('gt/gt_review.json','GT逐步核验'),('score.json','机器可读评分'),('verification.json','交付检查')])+'\n'
 if (out/'independent_verification.json').exists():text+=link(out/'independent_verification.json','独立回读验证')+'\n'
 (out/'report.md').write_text(text,encoding='utf-8');return result

def execute(root,out,config=None,offline=False,max_records=None,plan_only=False,resume=False,refresh_gt=False,authenticity_config=None,authenticity_reference=None):
 for key in ('annotation_samples_per_label','defense_semantic_action_limit'):
  if (authenticity_config or {}).get(key) is not None:raise ValueError('Full semantic review requires removing obsolete limit: '+key)
 root=Path(root).resolve();out=Path(out).resolve()
 if resume:
  if out.is_relative_to(root) or root.is_relative_to(out):raise ValueError('Unsafe resume paths')
  state=read(out/'workflow.json')
  if state['original_input']!=str(root):raise ValueError('Resume input mismatch')
  source=Path(state['source_root'])
  for m in read(out/'archive_manifest.json') if (out/'archive_manifest.json').exists() else []:
   if m.get('archive_sha256') and sha(m['archive'])!=m['archive_sha256']:raise ValueError('Archive changed since this run')
 else:
  root,out=protected(root,out);out.mkdir(parents=True);source,_=materialize(root,out)
  state={'original_input':str(root),'source_root':str(source),'started':stamp(),'python':sys.executable,'stage':'mapping'};save(out/'workflow.json',state)
 mapping=out/'mapping';mapping.mkdir(exist_ok=True);gtout=out/'gt';gtout.mkdir(exist_ok=True)
 reviewer=Reviewer(out/'ai',offline=offline)
 if (mapping/'validated_config.json').exists() and resume:cfg=read(mapping/'validated_config.json')
 elif config is not None or offline:
  prepare(source,mapping);cfg=config or {};save(mapping/'validated_config.json',cfg);save(mapping/'mapping_validation.json',{'mode':'explicit_configuration' if config is not None else 'offline_native_adapters','not_AI_generated':True})
 else:cfg=propose(source,mapping,reviewer)
 print('mapping_validated',flush=True)
 defense_dir=mapping/'defense'
 from defense_input import ensure_audit
 from ingest import discover
 defense=ensure_audit(source,discover(source,cfg),defense_dir)
 state['defense']={'status':defense['status'],'files':[x['path'] for x in defense['files']],'report':str(defense_dir/'report.md')}
 save(out/'workflow.json',state)
 print(json.dumps({'defense_materials':state['defense']},ensure_ascii=True),flush=True)
 if plan_only:state.update(stage='plan_only',time=stamp());save(out/'workflow.json',state);return None
 normalized=out/'normalized'
 if resume and (normalized/'summary.json').exists():
  inv=read(normalized/'01_inventory.json')
  from ingest import source_hash
  for s in inv['files']:
   if s.get('sha256') and source_hash(source,s)!=s['sha256']:raise ValueError('Source changed; cannot resume '+s['path'])
  summary=read(normalized/'summary.json')
 else:
  state.update(stage='full_conversion');save(out/'workflow.json',state);summary=ingest_run(source,normalized,cfg,max_records)
 print('converted',summary['counts'].get('records'),summary['complete_input_scan'],flush=True)
 if offline or not summary['complete_input_scan']:
  gt={'status':'not_run_offline' if offline else 'not_run_incomplete_input','value':None,'upper':1,'steps':[]};save(gtout/'gt_review.json',gt)
 elif resume and (gtout/'gt_review.json').exists() and not refresh_gt:gt=read(gtout/'gt_review.json')
 else:
  if (gtout/'gt_review.json').exists():
   import shutil
   history=out/'history'/datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f');history.mkdir(parents=True)
   for name in ('gt/gt_review.json','report.md','score.json','verification.json','ai/usage.json'):
    src=out/name
    if src.exists():dest=history/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dest)
  state.update(stage='GT_semantic_review');save(out/'workflow.json',state);gt=review_steps(source,normalized,gtout,reviewer)
 result=finalize(out,gt)
 result['defense_materials']=state['defense']
 from reports import link
 with (out/'report.md').open('a',encoding='utf-8') as report:
  report.write('\n防御材料：'+('、'.join(state['defense']['files']) or '当前识别器未识别到；不证明不存在')+'。\n\n'+link(defense_dir/'report.md','防御对应文件、逐条提取与日志定位核验')+'\n')
 from annotation_semantics import review as review_annotation
 state.update(stage='annotation_semantic_review');save(out/'workflow.json',state)
 annotation_out=out/'annotation_semantics'
 if annotation_out.exists():annotation_out=out/('annotation_semantics_'+datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f'))
 annotation_review=review_annotation(source,normalized,annotation_out,reviewer,complete=summary['complete_input_scan'])
 from authenticity import analyze as analyze_authenticity
 state.update(stage='authenticity_time_and_behavior');save(out/'workflow.json',state)
 authout=out/'authenticity'
 if authout.exists():authout=out/('authenticity_'+datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f'))
 auth_features,auth_scores=analyze_authenticity(normalized,authout,authenticity_config,authenticity_reference,annotation_review)
 with (authout/'report.md').open('a',encoding='utf-8') as report:report.write('\n'+link(annotation_out/'report.md','R01逐条标注语义判断与证据')+'\n')
 result['authenticity']={'annotation_report':str(annotation_out/'report.md'),'annotation_score':auth_scores['annotation_score'],'report':str(authout/'report.md'),'status':auth_scores['status'],'time_score':auth_scores['time_score'],'behavior_score':auth_scores['behavior_score'],'total':auth_scores['authenticity_total']}
 save(out/'score.json',result)
 from reports import link
 with (out/'report.md').open('a',encoding='utf-8') as report:report.write('\n'+link(authout/'report.md','真实性：标注语义、时间特征与行为分布')+'（独立模块，不并入全面性分数）\n')
 from adversarial import analyze as analyze_adversarial
 state.update(stage='adversarial');save(out/'workflow.json',state)
 advout=out/'adversarial'
 if advout.exists():advout=out/('adversarial_'+datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f'))
 adversarial=analyze_adversarial(source,normalized,defense_dir,advout,reviewer)
 result['adversarial']={'report':str(advout/'report.md'),'score':adversarial['score'],'evidence_score':adversarial['evidence_score'],'unknown_metrics':adversarial['unknown_metrics']}
 (out/'completeness_report.md').write_bytes((out/'report.md').read_bytes())
 from quality_summary import write as write_quality
 quality=write_quality(out,result,auth_scores,adversarial,authout,advout)
 result['quality']=quality;save(out/'score.json',result)
 verification={'time':stamp(),'input_complete':summary['complete_input_scan'],'record_partition':summary['counts']['records']==summary['counts'].get('valid_records',0)+summary['counts'].get('incomplete_records',0),
  'label_partition':sum(summary['labels'].values())==summary['counts']['records'],'score_formula':result['score'] is None or abs(result['score']-100*sum(m['value'] or 0 for m in result['metrics'].values())/7)<1e-10,
  'no_old_result_dependency':not summary['historical_result_dependency'],'no_original_source_writes':True,'new_GT_reply_validity':[{'id':s['step_id'],'accepted':s['valid_review']} for s in gt.get('steps',[])]}
 save(out/'verification.json',verification)
 verification['quality_formula']=quality['total_score'] is None or abs(quality['total_score']-sum(v['contribution'] for v in quality['dimensions'].values()))<1e-10
 verification['adversarial_metrics']=sorted(adversarial['metrics']);verification['unknowns_preserved']=all(adversarial['metrics'][k]['value'] is None for k in adversarial['unknown_metrics'])
 save(out/'verification.json',verification)
 state.update(stage='complete' if result['input_complete'] else 'needs_review',completed=stamp(),score=result['score'],quality_status=quality['status'],total_score=quality['total_score']);save(out/'workflow.json',state)
 save(out/'artifact_manifest.json',{'time':stamp(),'artifacts':[{'path':p.relative_to(out).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)} for p in out.rglob('*') if p.is_file() and 'source' not in p.relative_to(out).parts and p.name!='artifact_manifest.json']})
 print(json.dumps({'total_score':quality['total_score'],'status':quality['status'],'report':str(out/'report.md')},ensure_ascii=False),flush=True);return result

def main(argv=None):
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',required=True,type=Path,help='Dataset directory (read-only)');p.add_argument('--output',type=Path,required=True,help='New result directory outside input');p.add_argument('--config',type=Path,help='Explicit field/label mapping JSON');p.add_argument('--offline',action='store_true',help='Disable all external model requests');p.add_argument('--max-records',type=int,help='Preview record limit; no dataset-wide score');p.add_argument('--plan-only',action='store_true',help='Inspect material roles and mappings without full scoring');p.add_argument('--resume',action='store_true',help='Resume unchanged input and configuration');p.add_argument('--refresh-gt',action='store_true',help='Recheck GT on resume; retain earlier reviews');p.add_argument('--authenticity-config',type=Path,help='Advanced statistical configuration JSON');p.add_argument('--authenticity-reference',type=Path,help='Alternative compatible reference JSON')
 p.add_argument('--env-file',type=Path,help='Explicit .env path; defaults to project root .env');p.add_argument('--version',action='version',version=SYSTEM_NAME+' '+VERSION)
 a=p.parse_args(argv);out=a.output or BASE/'runs'/('pipeline_'+datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f'))
 try:
  from runtime_config import configure,settings
  configure(a.env_file);settings(require_key=not a.offline)
  from authenticity import checked_path
  result=execute(a.input,out,read(a.config) if a.config else None,a.offline,a.max_records,a.plan_only,a.resume,a.refresh_gt,read(checked_path(a.authenticity_config)) if a.authenticity_config else None,a.authenticity_reference)
 except Exception as exc:
  if (out/'workflow.json').is_file() and not out.resolve().is_relative_to(a.input.resolve()) and not a.input.resolve().is_relative_to(out.resolve()):save(out/'pipeline_error.json',{'type':type(exc).__name__,'message':str(exc),'time':stamp()})
  print(json.dumps({'error':str(exc),'type':type(exc).__name__,'output':str(out)},ensure_ascii=True),flush=True);raise SystemExit(1)
 if result is not None and not result['input_complete'] and not a.max_records:raise SystemExit(2)

if __name__=='__main__':main()
