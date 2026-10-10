# 高级配置与维护

本文面向需要更换接口参数、排查特殊格式或维护代码的人员。普通使用者只需阅读[使用说明](../USAGE.md)，无需手写字段映射或理解下面的参数。

## 模型接口的完整设置


将根目录`.env.example`复制为`.env`，编辑变量值。模板只包含空接口密钥，不含真实凭据。

| 变量 | 说明 |
| --- | --- |
| AI_API_KEY | 当前服务的密钥；本机回环地址可留空，远程服务必填 |
| AI_BASE_URL | API根地址，例如服务文档所给的`https://主机/v1`；程序追加`/chat/completions`，不要填完整请求路径 |
| AI_MODEL | 服务实际提供的模型名称，必须显式填写 |
| AI_TIMEOUT_SECONDS | 单次请求超时，默认180秒，范围1—600 |
| AI_JSON_MODE | true默认，发送`response_format: {type: json_object}`；不支持此参数的服务设false |
| AI_TEMPERATURE | 默认omit不发送；也可设0—2的数值，模型不支持温度时保持omit |
| AI_TOKEN_PARAMETER | 默认max_tokens；要求新版参数的模型设max_completion_tokens |
| AI_THINKING | 默认omit不发送；只有支持`thinking.type`扩展的服务才设置disabled/enabled |

模板预填DeepSeek配置。切换云服务时同时替换地址、模型、密钥，将`AI_THINKING`改为`omit`，再按服务支持情况配置其他参数。支持范围是OpenAI兼容的Chat Completions协议：请求含system/user消息，响应含`choices[0].message.content`和`finish_reason=stop`。不支持Anthropic原生Messages、OpenAI Responses或云服务专属认证协议；这些服务需使用其兼容入口或兼容网关。不同模型仍需满足JSON回答和证据引用要求。

接入自选兼容服务的配置结构如下，地址、模型和密钥由使用者填写：

```dotenv
AI_BASE_URL=https://your-api-host/v1
AI_MODEL=your-model-name
AI_API_KEY=
AI_TIMEOUT_SECONDS=180
AI_JSON_MODE=true
AI_TEMPERATURE=omit
AI_TOKEN_PARAMETER=max_tokens
AI_THINKING=omit
```

本地部署使用其实际回环地址，例如`http://127.0.0.1:8000/v1`，模型填本地服务公布的名称，无认证服务可将`AI_API_KEY`留空。只对localhost、127.0.0.1、::1允许HTTP，其他地址必须HTTPS。URL不得包含用户名、密码、查询参数或片段；请求不跟随重定向。服务要求的路径前缀可包含在BASE_URL内。

默认读取项目根目录的`.env`，不依赖当前工作目录。进程环境变量覆盖同名文件值。支持空行、注释、单/双引号的单行字面值和可选export前缀，不执行命令、不做变量展开、不支持多行值。可用`--env-file`选择服务配置文件。

旧`DEEPSEEK_API_KEY/BASE_URL/MODEL/TIMEOUT_SECONDS`四个变量继续兼容；**出现任何`AI_*`配置后，整组旧配置都不再回退使用**，防止将原服务密钥误发到新地址。旧变量的地址仍限定DeepSeek；新服务必须配置完整AI变量组。

程序不自动切换服务或反复试探参数。HTTP 400通常需检查模型/兼容选项，401需检查密钥，其他错误按服务定义处理。错误记录不打印认证头或任意服务器错误体。`AI_JSON_MODE=false`只取消接口参数，提示词和本地解析仍要求严格JSON对象；非JSON或被截断的回复会保留原文并报告错误。

所有AI步骤共用同一配置。请求、响应、接口地址和模型与token用量留在输出的AI审计目录，不保存认证头。缓存由**完整请求体和接口地址**共同标识，跨服务不会混用；相同接口、模型和请求可以复用。模型或服务变更后使用新的输出目录，避免复用上层已完成的分析阶段。兼容性自动化测试使用模拟API，不代表所有云服务或模型都已在线测试。

## 完整命令参数


命令中的中文路径是待替换的参数说明，不是随附样例数据。

```bash
python run.py --input "数据集文件夹路径" --output "新的结果文件夹路径"
python run.py --input "数据集文件夹路径" --output "新的结果文件夹路径" --offline
python run.py --input "数据集文件夹路径" --output "新的计划目录" --plan-only
python run.py --input "数据集文件夹路径" --output "新的预览目录" --max-records 10000
python run.py --input "数据集文件夹路径" --output "新的结果文件夹路径" --config "字段映射JSON路径"
python run.py --input "数据集文件夹路径" --output "已有结果文件夹路径" --resume
```

| 参数 | 作用 |
| --- | --- |
| --input | 必需；数据集根目录 |
| --output | 必需；输入之外的新空目录，恢复模式除外 |
| --env-file | 指定API环境文件 |
| --offline | 不联网，不执行模型语义核验 |
| --plan-only | 完成材料识别、映射和防御清单后停止，不全量评分；在线时可能调用AI做映射 |
| --max-records | 限量预览；不能作为全数据集总分 |
| --config | 读取明确字段/角色/标签JSON映射，绕过AI映射；在线时仍执行GT语义核验 |
| --resume | 核对来源后继续同一运行，不更换输入、映射或协议 |
| --refresh-gt | 配合恢复重新核验GT，保存旧结论；相同请求仍可命中本地缓存 |
| --authenticity-config | 高级JSON配置：时间统计及语义抽样参数 |
| --authenticity-reference | 指定符合参考协议的聚合参数JSON；默认使用随附THEIA参数 |
| --version / --help | 查看版本或命令行参数 |

恢复不会自动发现所有配置语义变化。修改字段映射、统计基准、算法版本或待评文件集合时，使用新输出目录；完整扫描之前不要删除解压目录、规范化文件或阶段缓存。更换模型或服务应新开输出目录，避免把旧语义结果当成新模型结果。

## 程序退出状态

正常完成或主动选择的预览返回0；异常返回1；未指定预览但输入未完整处理返回2。正常退出不代表材料齐全，程序接入时还需读取评分结果中的状态。输出字段见[内部字段说明](INPUT_OUTPUT.md)。

## 测试与发布


```bash
python run_tests.py
python run_tests.py --temp-dir "测试临时文件所在磁盘目录"
python scripts/package_release.py --output "发布ZIP的完整路径"
```

测试动态生成临时记录，用模拟API覆盖在线分支，不调用真实接口、不需要真实密钥，退出时自动清理临时文件。自动化测试配置对Windows/Linux和Python 3.9/3.12执行同一测试；本机通过不代表云端自动化测试已经执行。

打包脚本使用白名单，只包含入口、依赖、src、resources、docs、tests、脚本、CI和.env.example，排除真实.env、数据、输出、缓存和Git目录，并扫描疑似密钥及绝对个人路径。目标ZIP已存在则拒绝覆盖。

提交前执行`git status --short`和`git check-ignore .env`，确认.env被忽略。不要使用强制添加将真实密钥、数据或输出绕过忽略规则加入仓库。发布内容以根目录README和docs为准，不附带数据集演示、评估榜单或本机测试报告。

## 语义抽样与恢复

1.1.1协议为`fixed-evidence-v3-step-sampling`。默认不需要额外配置；如需调整，通过`--authenticity-config`传入JSON：

| 配置项 | 默认值 | 含义 |
| --- | ---: | --- |
| annotation_samples_per_step | 10 | 每步最多抽中记录数，整数1—100 |
| annotation_samples_per_label | 10 | 未关联步骤的每种标签最多抽中记录数，整数1—100 |
| defense_semantic_action_limit | 40 | 防御动作样本上限，整数1—1000；null表示全部动作 |

固定输入和配置会选择相同样本；不得按模型结论选择易通过的记录。调整样本量会影响分数和用量，横评时保持配置一致。模型每批最多4个目标，拆批不再导致逐条扫描全部标签。终端先显示计划，再每10批及末批显示进度；ETA仅代表当前阶段。

中断后输入及模型不变可用`--resume`。1.1.0升级到1.1.1时允许复用同一运行的解析结果和未改变的请求；R01/A04使用新协议重建证据与判断，旧部分语义结果不自动沿用，新报告可能带时间后缀。其他来源、映射或参考变化仍应使用新输出目录。

离线未核验、样本引用失败及材料不足记0；未抽中不作为错标。A04采用样本分母，A03只报告样本已证实的措施种类。输入、选择规则、请求、回复、校验和数量均留档。抽样不能保证发现每个错误，不输出全量正确率或统计置信区间。
