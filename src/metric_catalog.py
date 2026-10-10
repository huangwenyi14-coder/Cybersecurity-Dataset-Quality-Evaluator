"""Stable public metric IDs, labels, formulas and weights for protocol 1.0."""
VERSION = '1.1.0'
SYSTEM_NAME = 'Cybersecurity-Dataset-Quality-Evaluator'
SYSTEM_NAME_ZH = '数据集多指标质量评估系统'
DIMENSION_WEIGHTS = {'completeness': .35, 'authenticity': .40, 'adversarial': .25}
DIMENSION_NAMES = {'completeness': '全面性', 'authenticity': '真实性', 'adversarial': '对抗性'}
METRICS = {
 'C01': ('completeness','规模与可用性','有效独立记录比例','有效独立事件数 / 原始事件数 × 100',1/7),
 'C02': ('completeness','规模与可用性','攻击实例关联覆盖','已关联GT实例数 / 声明GT实例数 × 100',1/7),
 'C03': ('completeness','规模与可用性','明确标签覆盖','明确标签记录数 / 原始事件数 × 100',1/7),
 'C04': ('completeness','覆盖范围','战术覆盖','min(确认战术数 / 15, 1) × 100',1/7),
 'C05': ('completeness','覆盖范围','技术覆盖','100 × [1 − (1 − min(父技术数,30)/30)²]',1/7),
 'C06': ('completeness','覆盖范围','对象操作覆盖','命中的参考三元组种类 / 35 × 100',1/7),
 'C07': ('completeness','攻击过程','GT步骤支持','各GT实例完整支持步骤比例的平均值 × 100',1/7),
 'R01': ('authenticity','标注质量','标注语义支持','全部关联标注均获支持的步骤数 / 全部步骤数 × 100；无步骤时逐条核验全部已有标签',.2),
 'R02': ('authenticity','数据真实度','时间特征','速率、波动、连续性高斯分等权；按有效时间记录数加权',.4),
 'R03': ('authenticity','数据真实度','行为分布','三元组比例高斯分按分布权重汇总；按有效行为记录数加权',.4),
 'A01': ('adversarial','攻击复杂度','多阶段攻击关联','确认存在跨战术关联的实例数 / GT实例数 × 100',.25),
 'A02': ('adversarial','攻击复杂度','技术实现变种','有至少两种已确认子技术实现的父技术数 / 已观测父技术数 × 100',.25),
 'A03': ('adversarial','防御覆盖','缓解措施执行覆盖','经执行语义核验支持的ATT&CK缓解措施种类 / 冻结44项目录 × 100',.25),
 'A04': ('adversarial','防御覆盖','防御结果可核查性','执行与结果语义对应且引用核验通过的动作数 / 声明的唯一动作数 × 100',.25),
}
