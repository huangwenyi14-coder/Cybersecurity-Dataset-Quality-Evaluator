# 数据读取与内部字段说明

本文面向开发和格式适配人员，说明程序如何把不同材料转换成内部记录。**下文的统一字段由程序提取，不要求使用者按表重命名原始字段或补写材料。** 表中字段名描述当前适配范围；不能识别时，应记录原因并改进适配器，不能编造缺失信息。普通使用者阅读[使用说明](../USAGE.md)即可。

GT在本文中指已有的攻击过程说明，包括哪次攻击、有哪些步骤。

## 文件夹输入

`--input`接收存在的目录，不直接接收单个文件路径。目录可包含日志、标签、GT、防御材料及受支持压缩包。输出目录必须在输入树之外，且不能反向包含输入目录。系统不要求目录名对应某个已知数据集。

| 文件角色 | 用途 | 识别或关联依据 |
| --- | --- | --- |
| data | 原始事件、流或包记录 | 支持的原生结构、标准字段或经验证的映射 |
| label | 事件级标签或节点上下文标签 | 事件ID、物理锚点及标签字段 |
| ground_truth | 攻击实例、步骤及叙述 | scenario_name/scenario_id与storyline_steps/gt_steps |
| reference | 说明、聚合标签、元数据或防御侧材料 | 内容结构，不当作原始事件重复计数 |
| container | 压缩容器 | 展开后识别成员 |
| unsupported/excluded | 未适配或用户明确排除 | 记录原因，不能悄悄当作已处理 |

防御材料由独立清单补充其告警、策略、动作、结果类别，不要求改变原始数据角色。

## 统一事件字段

| 字段 | 类型/要求 | 含义 |
| --- | --- | --- |
| event_id | 非空字符串 | 规范化事件的可定位身份 |
| event_time | 对象，含value、unit、basis | 明确时间值、单位和时钟域 |
| subject_type | 支持的节点类型枚举 | 主体类型 |
| subject_id | 非空字符串 | 主体身份 |
| operation | 支持的操作枚举 | 发生的操作 |
| object_type | 支持的节点类型枚举 | 客体类型 |
| object_id | 非空字符串 | 客体身份 |
| provenance | 必需补充字段 | file、source_sha256及offset/row/packet之一；可用时保留length、record_sha256 |

时间单位支持s、ms、us、ns、iso8601，时钟基准支持utc、relative、local_unspecified。规范化字段模式见`resources/event.schema.json`；运行时还检查空白/占位字符串、时间解释和原始定位。

扩展字段包括native_id、native_type、host、label、label_evidence、instance_ids、step_ids及extensions中的command、target_path、网络五元组、包长、TCP标志等。只有原始记录实际提供且适配器能解释时才保留，不要求AI生成缺失值。

## 标签与攻击过程说明的内部关联规则

| 材料 | 程序当前识别的字段 | 内部连接方式 |
| --- | --- | --- |
| 内嵌标签 | label及对应事件字段 | 随原事件保存；未知枚举不猜测 |
| 事件ID标签 | edge_uuid/event_uuid/record_id/uuid/flow_id之一，label/class | 与事件原生ID连接；可用data_file/source_file和host限定作用域 |
| 物理标签 | relative_path、byte_offset、byte_length、record_sha256及label | 回读字节范围并校验哈希；可附source_format、physical_record_id |
| 实例与步骤连接 | instance_id/attack_chain/scenario_id；storyline_id/step_id | 在标签或事件中明确关联实例和步骤 |
| GT实例 | scenario_name或scenario_id | 声明实例边界 |
| GT步骤 | storyline_steps或gt_steps中的对象；含storyline_id/step_id/id及叙述字段 | 提取步骤ID用于连接，叙述交给限定证据语义核验 |

支持将benign/normal/background等明确文字归为良性，attack/malicious/anomaly等归为恶意；contaminated为单独的明确状态。数字、任意类别名称需用`label_map`声明。节点标签只保留上下文，不能自动当作严格事件标签。聚合技术声明不作为逐日志技术命中的证据。

PDF、图片或自由文本GT目前不能自动转换为上述结构。AI目录映射也不是任意GT格式转换器；这类输入需要额外提取或适配。

## 开发与排错用的手动映射（可选）

常规运行由系统自动识别。只有开发、特殊格式适配或排错时才使用本节配置，不属于普通用户的准备步骤。

模型配置放在`.env`；文件字段、标签和值映射通过`--config`指向单独JSON。顶层支持以下键：

| 键 | 结构与用途 |
| --- | --- |
| files | 对象：输入相对路径或glob模式→文件配置；同一文件同时命中多个模式会报错 |
| ignore | 显式排除的相对路径glob列表；排除范围会记录在清单中 |
| label_map | 原标签字符串→标准标签状态的对象 |

每个文件配置可包含role、format、schema、delimiter、fields、constants、values、time_unit、time_basis。data映射的`fields`为规范字段名→源字段路径；允许timestamp、native_id、record_id、source、source_type、operation、target、target_type、command、target_path、host、label、instance_id、step_id等。源路径可用点分形式，也支持实际键名自身带点的结构。

`constants`仅用于用户明确声明的固定语义；`values`为目标字段下的原值→规范值映射。标签文件fields映射目前读取顶层源键，不提供任意复杂连接表达式。不要在映射文件中放API key。显式配置由用户负责语义正确性，处理阶段仍会执行字段及连接检查。

## 防御动作与结果的内部关联规则

| 材料 | 字段要求 |
| --- | --- |
| 动作声明 | action_id、action_type、target、execution_event_ids；可附host、mitigation_id |
| 结果声明 | 同一action_id、result_status或outcome、result_event_ids |
| 执行事件 | 满足七字段，原始结构化记录含同一action_id及相同目标，行为含义由模型核验 |
| 结果事件 | 原始记录含同一action_id及结果证据，目标、主机、时钟对应，时间不早于执行；模型核验结果含义 |

引用ID可用规范化event_id或能唯一解析的native_id。动作类型不再限于6种规则名称，由模型结合实际执行记录，在44项ATT&CK缓解措施目录中归类。明确success、succeeded、failed、failure、partial状态另做一致性检查；其他结果文本由模型解释并引用。规则见[评分规则](SCORING.md)。当前原始事件核查适用于可按字节定位的结构化JSON/XML记录；不是所有厂商CSV动作表的通用执行证明。自由文本或缺少明确动作连接的材料仍需补充适配，系统不能自动编造执行关联。

## 格式支持范围

| 类型 | 已实现内容 | 限制 |
| --- | --- | --- |
| JSON/JSONL、数组JSON | 流式解析，支持标准事件和明确字段映射 | 单个巨大对象需要相应内存；未知语义不能凭空补齐 |
| CSV/TSV | 分隔符/字段识别、行定位及映射 | 特殊分隔符和数字标签可能需要配置 |
| Sysmon/Windows XML及部分JSON | 已适配事件类型的主体、对象、操作和时间 | 非全部Event ID；原生EVTX未适配 |
| DARPA TC CDM JSON | 节点声明索引、事件二次解析、事件级标签连接 | 大型节点和标签索引需要内存；节点标签不扩散 |
| ECAR、部分ETW | 支持的原生字段、子类型、进程/对象及操作 | 未知子类型保留缺项；相对时钟不作为UTC |
| Zeek JSON、CICIDS类流CSV | 地址、端口、协议、流或事件时间及已映射字段 | 流不等于单包；部分记录无完整双节点关系 |
| 经典PCAP | 包时间、IP、端口、协议、包长、定位、可见TCP标志 | 无完整流重组/应用层解析；加密内容不可恢复；部分链路类型不支持 |
| PCAPNG | 单section中的IDB/EPB形态 | 多section、部分块类型、IPv6扩展头尚未完整支持 |
| ZIP/TAR/TAR.GZ/TGZ | 安全展开及成员哈希 | 必须有额外解压空间；拒绝链接与路径冲突 |
| PDF/图片/任意二进制 | 保留文件角色或未支持原因 | 不提供通用日志、标签或GT识别 |

## 输出目录与接口

| 路径 | 内容 |
| --- | --- |
| report.md | 系统主报告：总分、连续编号指标、原因与明细链接 |
| quality_score.json | 统一公开评分接口，全部14个metric.score为0—100数值 |
| completeness_report.md、score.json | 全面性及阶段汇总；score.json顶层score是全面性分数，不能当总分 |
| workflow.json | 输入位置、解释器和阶段状态 |
| mapping/ | 内容样本、映射方案、实际配置和验证 |
| mapping/defense/ | 防御文件清单、证据及连接检查 |
| normalized/ | 规范化完整/不完整事件、标签连接、规则命中、数量、类型和缺项 |
| gt/、ai/ | GT证据、模型回复、本地校验、请求哈希及用量 |
| annotation_semantics/ | R01全部步骤及抽中记录清单、标签与步骤归属的语义判断、具体引用和本地校验；恢复时可能带时间后缀 |
| authenticity/ | 标注、时间窗口、行为分布、冻结参考、参数和分项 |
| adversarial/ | A01关联、A02变种、A03/A04执行与结果核查 |
| adversarial/defense_semantics/ | A03/A04的选择范围、目录、源记录、逐动作语义判断与本地引用检查 |
| verification.json | 记录分区、标签分区、全量状态与公式检查 |
| artifact_manifest.json | 输出文件SHA-256清单 |
| source/、archive_manifest.json | 输入含压缩包时的临时展开及成员映射 |
| pipeline_error.json | 发生异常时的类型、消息与时间 |

`quality_score.json`的`metrics`按C01—C07、R01—R03、A01—A04顺序输出，每项提供dimension、group、name、score、formula、weight_within_dimension、status、reason、zero_policy_applied及可用的分子分母。`total_score=null`仅用于输入未完成；底层证据文件中的null保持诊断含义，不覆盖公开评分政策。

运行产物可能包含源日志内容、路径、网络信息和模型证据，不属于GitHub发布内容。保留原始输入和哈希清单才能回查证据。完成核验后可以自行清理可重建SQLite或临时解压，但清理后不能直接依赖原运行恢复，回读定位需重新展开原包。

R01的`coverage`包含评分单位、总步骤数、样本检查数量、判断计数，以及`sampling`中的每步总体/样本数量、未关联标签各类总体/样本数量和整体抽中比例。公开分母有步骤时为全部步骤，无步骤时为全部标签样本。`annotation_semantics/review.json`的`steps`列出每步总体与样本判断，`rows`只包含抽中记录；无日志步骤仍列出。

A03/A04的`scope`包含动作总体、样本量、比例、未抽中编号和扫描状态。A04公开分母为全部抽中动作，包括抽中但未核验的动作；不把未抽中当错误。A03仅统计抽中动作中已证实的措施种类。`plan.json`及`progress.json`记录模型批次计划和进度，终端也定期输出。
