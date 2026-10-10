"""Inspection contract: failed conversion is not automatically a bad dataset."""
def checks(summary):
 c=summary['counts'];n=c.get('records',0);valid=c.get('valid_records',0)
 return [
  {'id':'I01','name':'输入处理范围','status':'pass' if summary['complete_input_scan'] else 'needs_review','evidence':{'records':n,'unsupported':summary['unsupported_files'],'truncated':summary['truncated'],'parse_errors':summary['errors']},'interpretation':'未处理完整时不发布整个数据集分数'},
  {'id':'I02','name':'七字段完整性及值校验','status':'pass' if n and valid==n else 'needs_review','evidence':{'valid':valid,'incomplete':c.get('incomplete_records',0),'field_errors':summary['missing_fields']},'interpretation':'缺字段可能是源数据缺失，也可能是适配器未映射；逐条原始定位核查'},
  {'id':'I03','name':'事件身份一致性','status':'conflict' if c.get('identity_content_conflicts',0) else 'pass','evidence':{'unique':c.get('unique_records',0),'duplicates':c.get('duplicate_identity_records',0),'identity_content_conflicts':c.get('identity_content_conflicts',0)},'interpretation':'相同行为不自动去重；相同原生身份不同内容必须留痕'},
  {'id':'I04','name':'标签匹配与冲突','status':'conflict' if c.get('label_conflicts',0) or c.get('duplicate_label_conflicts',0) else 'needs_review' if summary['unmatched_label_rows'] else 'pass' if summary['matched_label_rows'] or any(summary['labels'].get(k,0) for k in ('benign','malicious','contaminated')) else 'unknown',
   'evidence':{'rows':summary['label_rows'],'matched_rows':summary['matched_label_rows'],'unmatched_rows':summary['unmatched_label_rows'],'conflicts':c.get('label_conflicts',0),'duplicate_label_conflicts':c.get('duplicate_label_conflicts',0),'states':summary['labels']},'interpretation':'无标签为未知；节点标签不扩散；不猜数字类别和跨文件 ID 作用域'},
  {'id':'I05','name':'GT 结构关联','status':'pass' if summary['declared_steps'] and set(summary['declared_steps'])<=set(summary['observed_steps']) else 'needs_review' if summary['declared_steps'] else 'unknown','evidence':{'declared_steps':summary['declared_steps'],'observed_steps':summary['observed_steps']},'interpretation':'关联到步骤 ID 不等于证明步骤叙述；C07 语义核验另做'},
  {'id':'I06','name':'CDM 节点引用字典','status':'conflict' if summary['CDM_entity_conflicts'] else 'pass' if summary['CDM_entity_declarations'] else 'not_applicable','evidence':{'declarations':summary['CDM_entity_declarations'],'type_conflicts':summary['CDM_entity_conflicts']},'interpretation':'节点先索引后解析事件；类型冲突时不给引用臆造类型'},
  {'id':'I07','name':'物理 GT 完整覆盖','status':'needs_review' if summary['physical_GT_uncovered_ranges'] else 'pass','evidence':summary['physical_GT_uncovered_ranges'],'interpretation':'物理标签之外的有效字节不能默认为不存在日志'},
 ]
