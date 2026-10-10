"""All public metric scores use 0..100 with fixed weights and explicit zero reasons."""
from core import *
from metric_catalog import METRICS, DIMENSION_NAMES, DIMENSION_WEIGHTS, SYSTEM_NAME, SYSTEM_NAME_ZH, VERSION


def compose(completeness, authenticity, adversarial):
    full = all(x['input_complete'] for x in (completeness,authenticity,adversarial))
    raw = {k:dict(v) for k,v in completeness['metrics'].items() if k in METRICS}
    for mid,key in [('R01','annotation_score'),('R02','time_score'),('R03','behavior_score')]:
        value = authenticity.get(key)
        raw[mid] = {'value': None if value is None else value/100,
                    'reason': authenticity.get('annotation_detail',{}).get('reason','') if mid=='R01' else authenticity.get('scope','Reference statistical similarity'),
                    'status': authenticity.get('annotation_detail',{}).get('status','computed') if mid=='R01' else 'not_available' if value is None else 'computed'}
        if mid=='R01':
            detail=authenticity.get('annotation_detail',{})
            raw[mid].update(numerator=detail.get('supported'),denominator=detail.get('denominator'),coverage=detail)
    raw.update({k:dict(v) for k,v in adversarial['metrics'].items() if k in METRICS})
    metrics = {}; review = []
    for mid,(dimension,group,name,formula,weight) in METRICS.items():
        r = raw.get(mid, {'value':None,'reason':'No metric evidence supplied'})
        value = r.get('value')
        score = 100 * (r.get('lower',0.) or 0.) if value is None else 100*value
        if not 0 <= score <= 100:
            raise ValueError('Metric score out of range: '+mid)
        incomplete = value is None
        if incomplete: review.append(mid)
        metrics[mid] = {'dimension':dimension,'group':group,'name':name,'score':score,
                        'formula':formula,'weight_within_dimension':weight,
                        'status':'evidence_incomplete' if incomplete else r.get('status','computed'),
                        'zero_policy_applied':incomplete and score==0,'reason':r.get('reason',''),
                        'numerator':r.get('numerator'),'denominator':r.get('denominator')}
    metrics['R01']['coverage']=raw['R01'].get('coverage',{})
    if metrics['R01']['status'] in ('semantic_review_not_run','not_run_offline','not_run_incomplete_input','no_explicit_event_labels','no_annotation_claims','semantic_review_incomplete'):
        metrics['R01']['zero_policy_applied']=metrics['R01']['score']==0
        if 'R01' not in review:review.append('R01')
    elif any(n for state,n in metrics['R01']['coverage'].get('states',{}).items() if state!='supported'):
        if 'R01' not in review:review.append('R01')
    for mid in ('A03','A04'):
        metrics[mid]['scope']=raw.get(mid,{}).get('scope',{})
        if metrics[mid]['status'] in ('not_run_offline','no_defense_actions','semantic_evidence_partial'):
            if mid not in review:review.append(mid)
            if metrics[mid]['score']==0:metrics[mid]['zero_policy_applied']=True
    dimensions = {}
    for dim,weight in DIMENSION_WEIGHTS.items():
        score = sum(m['score']*m['weight_within_dimension'] for m in metrics.values() if m['dimension']==dim)
        dimensions[dim] = {'name':DIMENSION_NAMES[dim], 'score':score, 'weight':weight, 'contribution':score*weight}
    return {'system':SYSTEM_NAME,'version':VERSION,'protocol':'fixed-evidence-v2-all-semantic',
            'input_complete':full,'total_score':sum(d['contribution'] for d in dimensions.values()) if full else None,
            'dimensions':dimensions,'metrics':metrics,'review_required':review,
            'status':'input_incomplete' if not full else 'scored_with_evidence_gaps' if review else 'scored',
            'score_policy':'Missing/unverified evidence earns zero; confirmed partial contribution is retained. Parsing/adaptation errors are recorded separately. No weight redistribution.',
            'weights':DIMENSION_WEIGHTS}


def write(out,c,a,d,authout,advout):
    from reports import table,link
    result=compose(c,a,d);save(out/'quality_score.json',result)
    summary=read(out/'normalized/summary.json')
    usage=read(out/'ai/usage.json') if (out/'ai/usage.json').exists() else {'calls':[],'usage':{}}
    total='未完成全量扫描，不发布总分' if result['total_score'] is None else f"{result['total_score']:.2f}/100"
    text=f'# {SYSTEM_NAME_ZH}\n\n{SYSTEM_NAME} · {VERSION}\n\n'
    text+='输入：`'+read(out/'workflow.json')['original_input']+'`。\n\n'
    text+=f'**总分：{total}**。状态：`{result["status"]}`。\n\n'
    text+='缺少或未能证实的材料不获分，分母为零时按协议记0而不执行除法。适配失败、离线未核验与材料缺失分别留痕；0分不证明现实中从未发生对应行为。\n\n'
    text+=table(['维度','权重','得分/100','总分贡献'],[[x['name'],f"{x['weight']:.0%}",f"{x['score']:.2f}",f"{x['contribution']:.2f}"] for x in result['dimensions'].values()])
    text+='\n'+table(['一级','二级','编号','指标','得分/100','计算方法','证据状态'],[[DIMENSION_NAMES[m['dimension']],m['group'],k,m['name'],f"{m['score']:.2f}",m['formula'],m['status']] for k,m in result['metrics'].items()])
    text+='\n'+table(['输入检查','值'],[['原始事件数',summary['counts'].get('records',0)],['七字段完整事件数',summary['counts'].get('valid_records',0)],['不完整事件数',summary['counts'].get('incomplete_records',0)],['完整扫描',summary['complete_input_scan']],['未适配文件数',len(summary['unsupported_files'])],['解析/标签错误数',len(summary['errors'])],['AI请求记录数',len(usage['calls'])],['API返回token计数（含缓存来源，详见usage）',usage['usage'].get('total_tokens',0)]])
    ann=result['metrics']['R01'].get('coverage',{})
    text+=f"\nR01逐项核验：全部步骤 {ann.get('total_steps',0)} 个，关联记录已核验的步骤 {ann.get('reviewed_steps',0)} 个；记录范围 {ann.get('selected_records',0)} 条，具有合法判断 {ann.get('reviewed_records',0)} 条。无步骤时按全部已有标签记录评分。未核验项保留在分母，模型判断不等于人工真值。\n"
    text+='\n真实性为相对于冻结参考的统计相似度，须结合参与覆盖率；A01不代表完整攻击链重建；A02仅统计已识别子技术变种；A03按44项ATT&CK缓解措施参考目录归类；A04要求执行与结果的语义对应。未核验动作不计确认分。\n\n'
    for mid in result['review_required']:
        text+=f'- {mid}：{result["metrics"][mid]["reason"]}\n'
    text+='\n'+ '\n'.join(link(p,title) for p,title in [(out/'completeness_report.md','全面性明细'),(authout/'report.md','真实性明细'),(advout/'report.md','对抗性明细'),(out/'mapping/defense/report.md','防御文件及定位'),(out/'normalized/report.md','输入与标签统计'),(out/'quality_score.json','机器可读评分'),(out/'verification.json','交付检查')])+'\n'
    (out/'report.md').write_text(text,encoding='utf-8')
    return result
