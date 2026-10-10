"""Observable procedure rules, with explicit attribution and a complete catalog ledger.

No generic mmap->injection, port80->HTTP, or filename->execution inference.
Command rules measure an observed invocation/attempt, not successful completion.
"""
from core import *
import re,shlex

# rule_id, technique, tactic, executable alternatives, required arguments regex
COMMANDS=[
 ('system_info','T1082','TA0007','uname|hostname|systeminfo|sw_vers',r'.*'),
 ('user_identity','T1033','TA0007','whoami|id',r'.*'),
 ('network_config','T1016','TA0007','ifconfig|ipconfig|route|arp',r'.*'),
 ('ip_config','T1016','TA0007','ip',r'\b(addr|address|link|route)\b'),
 ('process_list','T1057','TA0007','ps|tasklist',r'.*'),
 ('network_connections','T1049','TA0007','netstat|ss',r'.*'),
 ('file_listing','T1083','TA0007','ls|find|locate|pwd|tree',r'.*'),
 ('account_enumeration','T1087.001','TA0007','getent',r'\bpasswd\b'),
 ('group_enumeration','T1069.001','TA0007','getent',r'\bgroup\b'),
 ('net_accounts','T1087.001','TA0007','net|net1',r'^user\s*$'),
 ('net_groups','T1069.001','TA0007','net|net1',r'^(localgroup|group)\s*$'),
 ('remote_host_probe','T1018','TA0007','ping',r'\S'),
 ('port_scan_tool','T1046','TA0007','nmap|masscan|zmap',r'\S'),
 ('unix_shell','T1059.004','TA0002','sh|bash|dash|zsh|ksh',r'(^|\s)-c\s+\S'),
 ('powershell','T1059.001','TA0002','powershell|pwsh',r'(^|\s)-(c|command|file|enc|encodedcommand)\s+\S'),
 ('windows_shell','T1059.003','TA0002','cmd',r'(^|\s)/(c|k)\s+\S'),
 ('python_script','T1059.006','TA0002','python|python2|python3',r'(^|\s)-c\s+\S|\S+\.py(\s|$)'),
 ('javascript','T1059.007','TA0002','node|nodejs',r'(^|\s)-e\s+\S|\S+\.js(\s|$)'),
 ('vbs_script','T1059.005','TA0002','wscript|cscript',r'\.vbs(\s|$)'),
 ('applescript','T1059.002','TA0002','osascript',r'(^|\s)-e\s+\S|\.scpt(\s|$)'),
 ('wmi_execution','T1047','TA0002','wmic',r'\bprocess\s+call\s+create\b'),
 ('scheduled_task','T1053.005','TA0003','schtasks',r'(^|\s)/create\b'),
 ('cron_edit','T1053.003','TA0003','crontab',r'(^|\s)-e(\s|$)'),
 ('service_install','T1543.003','TA0003','sc',r'^create\s+\S'),
 ('systemd_enable','T1543.002','TA0003','systemctl',r'\benable\s+\S'),
 ('linux_permissions','T1222.002','TA0112','chmod|chown',r'\S'),
 ('windows_permissions','T1222.001','TA0112','icacls|cacls',r'/(grant|deny|setowner|reset)\b'),
 ('create_account','T1136.001','TA0003','useradd|adduser',r'\S'),
 ('net_create_account','T1136.001','TA0003','net|net1',r'^user\b.*\s/add\b'),
 ('sudo_invocation','T1548.003','TA0004','sudo',r'\S'),
 ('wget_transfer','T1105','TA0011','wget',r'https?://\S'),
 ('curl_transfer','T1105','TA0011','curl',r'https?://\S'),
 ('ssh_remote','T1021.004','TA0008','ssh',r'\S'),
 ('rdp_remote','T1021.001','TA0008','mstsc|xfreerdp|rdesktop',r'\S'),
 ('smb_remote','T1021.002','TA0008','smbclient',r'//\S'),
 ('service_exec','T1569.002','TA0002','psexec|psexec64',r'\\\\\S'),
 ('archive_tar','T1560.001','TA0009','tar',r'(^|\s)-?[a-z]*c[a-z]*(\s|$)|--create'),
 ('archive_zip','T1560.001','TA0009','zip|rar|7z|7za',r'(^a\s+)|\.zip\b'),
 ('decode_base64','T1140','TA0005','base64',r'(^|\s)(-d|--decode)(\s|$)'),
 ('certutil_decode','T1140','TA0005','certutil',r'(^|\s)-decode\s'),
 ('certutil_transfer','T1105','TA0011','certutil',r'(^|\s)-urlcache\b.*https?://'),
 ('clear_eventlog','T1685.005','TA0112','wevtutil',r'^cl\s+\S'),
 ('timestomp','T1070.006','TA0005','touch',r'(^|\s)(-t|-d|-r)\s+\S'),
 ('stop_service','T1489','TA0040','systemctl',r'^stop\s+\S'),
 ('stop_win_service','T1489','TA0040','sc|net',r'^stop\s+\S'),
 ('remove_snapshots','T1490','TA0040','vssadmin',r'^delete\s+shadows\b'),
 ('container_deploy','T1610','TA0002','docker|podman',r'^run\s+\S'),
]

# Typed path operations are evaluated only when actual native fields supply the path.
PATHS=[
 ('startup_file','T1547.001','TA0003',{'create','write'},r'/start menu/programs/startup/'),
 ('cron_file','T1053.003','TA0003',{'create','write'},r'^/(etc/cron[^/]*|var/spool/cron)/'),
 ('systemd_file','T1543.002','TA0003',{'create','write'},r'^/(etc|usr/lib|lib)/systemd/system/[^/]+\.service$'),
 ('ssh_authorized_key','T1098.004','TA0003',{'create','write'},r'/\.ssh/authorized_keys$'),
 ('ld_preload','T1574.006','TA0005',{'create','write'},r'^/etc/ld\.so\.preload$'),
 ('shadow_read','T1003.008','TA0006',{'read'},r'^/etc/(shadow|gshadow)$'),
 ('history_read','T1552.003','TA0006',{'read'},r'/\.(bash_history|zsh_history)$'),
 ('private_key_read','T1552.004','TA0006',{'read'},r'/\.ssh/id_(rsa|ed25519|dsa|ecdsa)$'),
 ('browser_secrets','T1555.003','TA0006',{'read'},r'/(login data|logins\.json|key[34]\.db)$'),
 ('passwd_discovery','T1087.001','TA0007',{'read'},r'^/etc/passwd$'),
 ('document_collection','T1005','TA0009',{'read'},r'/(documents|desktop|home)/.*\.(docx?|xlsx?|pptx?|pdf|csv)$'),
 ('hosts_config','T1016','TA0007',{'read'},r'^/etc/(hosts|resolv\.conf)$'),
 ('system_info_file','T1082','TA0007',{'read'},r'^/(proc/(cpuinfo|version)|etc/os-release)$'),
]

def command_parts(command):
 command=str(command or '').strip()
 try:
  windows=bool(re.match(r'^["\']?[A-Za-z]:[\\/]',command))
  tokens=shlex.split(command,posix=not windows)
 except ValueError:tokens=command.split()
 if not tokens:return '',[]
 exe=tokens[0].strip('"\'').replace('\\','/').rsplit('/',1)[-1].lower()
 if exe.endswith('.exe'):exe=exe[:-4]
 return exe,[t.strip('"') for t in tokens[1:]]

def evaluate(e):
 hits=[]
 if e.get('operation')=='execute':
  exe,args=command_parts(e.get('command'));arg=' '.join(args)
  for rid,tid,tac,executables,pattern in COMMANDS:
   if args and all(a.lower() in ('--help','--version','-?') for a in args):continue
   if rid=='curl_transfer' and any(a in ('-I','--head') for a in args):continue
   if rid=='wget_transfer' and '--spider' in args:continue
   if re.fullmatch(executables,exe) and re.search(pattern,arg,re.I):hits.append((rid,tid,tac,'observed_command_invocation'))
 path=str(e.get('target_path') or '').replace('\\','/').lower()
 for rid,tid,tac,ops,pattern in PATHS:
  if e.get('operation') in ops and re.search(pattern,path,re.I):hits.append((rid,tid,tac,'observed_typed_path_operation'))
 result=[{'rule_id':r,'technique_id':t,'parent_id':t.split('.')[0],'tactic_id':a,'evidence_id':e['record_id'],
          'evidence':{k:e.get(k) for k in ('operation','command','target_path','label','locator')},'basis':b,
          'status':'supported' if e.get('label') in ('attack','malicious') else 'unattributed_candidate'} for r,t,a,b in hits]
 for h in result:
  if h['basis']=='observed_typed_path_operation' and e.get('operation')=='read':
   contextual_collection=h['rule_id']=='document_collection' and str(e.get('gt_step','')).endswith('collection')
   if not contextual_collection:
    h['status']='semantic_candidate';h['reason']='A library/routine read by an attack-labelled process does not establish discovery/credential/collection intent.'
 return result

