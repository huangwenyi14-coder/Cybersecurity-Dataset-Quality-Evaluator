"""Content-based streaming adapters. No dataset-name or historical-result dependency."""
from core import *
import io,re,struct,socket,zipfile,contextlib,xml.etree.ElementTree as ET

SKIP={'.git','.private','__pycache__','node_modules','.codex'}
NODEMAP={'Subject':'process','FileObject':'file','NetFlowObject':'network_endpoint','MemoryObject':'memory','Principal':'account','Host':'host'}
CDM_OPS={'EVENT_OPEN':'open','EVENT_READ':'read','EVENT_WRITE':'write','EVENT_CONNECT':'connect','EVENT_SENDTO':'send','EVENT_SENDMSG':'send','EVENT_RECVFROM':'receive','EVENT_RECVMSG':'receive','EVENT_CLONE':'spawn','EVENT_EXECUTE':'execute','EVENT_UNLINK':'delete','EVENT_SHM':'share_memory','EVENT_MPROTECT':'protect','EVENT_READ_SOCKET_PARAMS':'read_socket_parameters','EVENT_WRITE_SOCKET_PARAMS':'write_socket_parameters','EVENT_MODIFY_FILE_ATTRIBUTES':'modify_attributes'}

def key(k):return re.sub(r'[^a-z0-9]','',str(k).lower())
def columns(row):return {key(k):v for k,v in row.items() if k is not None}
def pick(row,*names):
 for n in names:
  value=row.get(key(n))
  if value is not None and str(value).strip()!='':return value
 return None
def canon_label(v,mapping=None):
 s=str(v or '').strip();low=s.lower()
 if mapping and s in mapping:return mapping[s]
 if low in ('benign','normal','background','legitimate'):return 'benign'
 if low in ('attack','malicious','anomaly','anomalous','malware'):return 'malicious'
 if low=='contaminated':return 'contaminated'
 if low in ('','-','unknown','unlabeled','unlabelled','none','null','nan'):return 'unknown'
 return 'unmapped' # Numeric and arbitrary class labels require a declared mapping.

def sources(root):
 for base,dirs,names in os.walk(root,followlinks=False):
  dirs[:]=sorted(d for d in dirs if d not in SKIP and not Path(base,d).is_symlink() and not getattr(Path(base,d),'is_junction',lambda:False)())
  for name in sorted(names):
   p=Path(base,name)
   if p.is_symlink() or not p.resolve().is_relative_to(root):continue
   rel=p.relative_to(root).as_posix()
   if p.suffix.lower()=='.zip':
    yield {'path':rel,'bytes':p.stat().st_size,'container_only':True}
    with zipfile.ZipFile(p) as z:
     for info in z.infolist():
      if info.is_dir():continue
      parts=Path(info.filename.replace('\\','/')).parts
      if '..' in parts or any(x in SKIP for x in parts) or info.filename.startswith(('/','\\')):continue
      yield {'path':rel+'!'+info.filename,'container':rel,'member':info.filename,'bytes':info.file_size,'crc32':info.CRC}
   else:yield {'path':rel,'bytes':p.stat().st_size}

@contextlib.contextmanager
def open_source(root,s):
 if s.get('container'):
  with zipfile.ZipFile(root/s['container']) as z:
   with z.open(s['member']) as f:yield f
 elif s['path'].lower().endswith('.gz') and not s['path'].lower().endswith('.tar.gz'):
  with gzip.open(root/s['path'],'rb') as f:yield f
 else:
  with (root/s['path']).open('rb') as f:yield f

def json_values(f):
 """Incremental JSONL / pretty object / top-level array, with byte anchors."""
 decoder=json.JSONDecoder();buf=b'';offset=0;array=False;started=False;done=False;index=0;closed=False;separator=False;after_comma=False
 while True:
  chunk=f.read(65536)
  if not chunk:done=True
  buf+=chunk
  while True:
   trim=len(buf)-len(buf.lstrip(b' \r\n\t'))
   offset+=trim;buf=buf[trim:]
   if not started and buf.startswith(b'\xef\xbb\xbf'):offset+=3;buf=buf[3:]
   if not started and buf:
    started=True
    if buf[:1]==b'[':array=True;offset+=1;buf=buf[1:];continue
   if closed and buf:raise ValueError('Extra data after JSON array')
   if array and buf:
    if separator:
     if buf[:1]==b',':offset+=1;buf=buf[1:];separator=False;after_comma=True;continue
     if buf[:1]!=b']':raise ValueError('Missing JSON array comma')
    if buf[:1]==b']':
     if after_comma:raise ValueError('Trailing JSON array comma')
     offset+=1;buf=buf[1:];closed=True;continue
   if not buf:break
   newline=buf.find(b'\n')
   if buf[:1]==b'{' and newline>=0:
    try:obj=orjson.loads(buf[:newline])
    except orjson.JSONDecodeError:pass
    else:
     raw=buf[:newline].rstrip(b'\r');index+=1;yield index,obj,{'offset':offset,'length':len(raw)},raw
     if array:separator=True;after_comma=False
     offset+=newline+1;buf=buf[newline+1:];continue
   try:
    txt=buf.decode('utf-8');obj,n=decoder.raw_decode(txt);length=len(txt[:n].encode('utf-8'))
   except (UnicodeDecodeError,json.JSONDecodeError):
    if done or len(buf)>64*1024**2:raise ValueError('Malformed JSON or record larger than 64 MiB at byte '+str(offset))
    break
   index+=1;raw=buf[:length];yield index,obj,{'offset':offset,'length':length},raw
   if array:separator=True;after_comma=False
   offset+=length;buf=buf[length:]
  if done:
   if buf.strip():raise ValueError('Trailing malformed JSON')
   if array and not closed:raise ValueError('Unterminated JSON array')
   break

def xml_row(raw):
 el=ET.fromstring(raw);row={}
 for node in el.iter():
  tag=node.tag.rsplit('}',1)[-1]
  if tag=='Data':row[node.attrib.get('Name','Data')]=node.text
  elif tag=='TimeCreated':row['timestamp']=node.attrib.get('SystemTime')
  elif tag=='Provider':row['ProviderName']=node.attrib.get('Name')
  elif tag in ('EventID','Computer','EventRecordID','Channel'):row[tag]=node.text
 return row

def flatten_windows(row):
 if 'Event' in row and isinstance(row['Event'],dict):row=row['Event']
 if 'System' not in row:return row
 result={}
 for k,v in row['System'].items():
  if isinstance(v,dict):
   if k=='TimeCreated':result['timestamp']=v.get('@SystemTime',v.get('SystemTime'))
   elif k=='Provider':result['ProviderName']=v.get('@Name',v.get('Name'))
   else:result[k]=v.get('#text',v.get('Value'))
  else:result[k]=v
 data=row.get('EventData',{})
 if isinstance(data,dict):
  entries=data.get('Data')
  if isinstance(entries,list):
   for d in entries:result[d.get('@Name',d.get('Name',''))]=d.get('#text',d.get('Value'))
  else:result.update(data)
 return result

def schema(row):
 if not isinstance(row,dict):return 'unknown'
 if 'datum' in row and isinstance(row['datum'],dict):return 'cdm'
 if {'event_id','event_time','subject_type','subject_id','operation','object_type','object_id'}<=set(row):return 'standard'
 row=flatten_windows(row);c=columns(row)
 if {'relativepath','byteoffset','bytelength','recordsha256'}<=set(c):return 'physical_labels'
 if 'scenario_name' in row and 'storyline_steps' in row:return 'story_gt'
 if 'storyline_steps' in row or 'gt_steps' in row:return 'story_gt'
 if 'scenario_sha256' in row and 'quality_standard_version' in row:return 'metadata'
 if 'quality_standard_version' in row and 'scenario_count' in row and 'corpus_issues' in row:return 'metadata'
 if 'schema_version' in row and 'email' in row:return 'artifact_manifest'
 if 'alert_id' in row and 'alert_reason' in row and 'location' in row:return 'derived_alerts'
 if 'source' in row and 'target' in row and 'operation' in row and 'timestamp' in row:return 'canonical'
 if ('action_id' in row and 'action_type' in row) or row.get('event_type') in ('defense_action','response_action'):return 'defense_actions'
 if ('action_id' in row and any(k in row for k in ('result_status','result','outcome'))) or row.get('event_type')=='defense_result':return 'defense_results'
 if 'policy_id' in row and any(k in row for k in ('configuration','rules','policy')):return 'defense_policy'
 if 'eventid' in c and any(x in c for x in ('processguid','computer','channel','providername','eventrecordid')):return 'windows'
 if 'eventname' in c and ('pname' in c or 'pid' in c):return 'etw'
 if 'object' in row and 'action' in row:return 'ecar'
 if any(x in c for x in ('label','vertexlabel','class')) and any(x in c for x in ('edgeuuid','eventuuid','recordid','uuid','flowid')):
  if not any(x in c for x in ('timestamp','operation','eventtype','protocol','flowduration','eventname','sourceip')):return 'id_labels'
 if 'source' in row and 'target' in row and any(x in row for x in ('operation','relation')):return 'canonical'
 if 'operation' in row and ('record_id' in row or 'timestamp' in row):return 'canonical'
 if ('protocol' in c or 'proto' in c) and any(x in c for x in ('flowduration','srcip','sourceip','srcaddr','destinationip','dstip')):return 'flow'
 if 'idorigh' in c and 'idresph' in c:return 'zeek'
 if 'zdrz001' in c and 'zdrz063' in c:return 'zdrz'
 if any(x in row for x in ('physical_id_set','ta_physical_ids')):return 'aggregate_labels'
 return 'unknown'

def probe(root,s):
 if s.get('container_only'):return {**s,'role':'container','format':'zip','reason':'member-level discovery; no extraction'}
 name=s['path'].lower()
 if name.endswith(('.tar.gz','.tgz','.tar','.7z','.evtx','.pdf','.png','.jpg','.docx','.xlsx','.xls')):
  return {**s,'role':'reference' if name.endswith(('.pdf','.png','.jpg','.docx')) else 'unsupported','format':Path(name).suffix,'reason':'preserved; no automatic interpretation of binary/archive contents'}
 if name.endswith(('.md','.rst','.yaml','.yml','.sh','.py','.exe','.dll')):return {**s,'role':'reference','format':'document','reason':'documentation/code is not data or executable instructions'}
 with open_source(root,s) as f:sample=f.read(65536)
 if sample[:4] in (b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4',b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d',b'\x0a\x0d\x0d\x0a'):
  return {**s,'role':'data','format':'pcap','schema':'packet','sample_sha256':hashlib.sha256(sample).hexdigest(),'reason':'capture magic bytes'}
 stripped=sample.lstrip(b'\xef\xbb\xbf \r\n\t');row=None;fmt='text'
 try:
  if stripped.startswith((b'{',b'[')):
   fmt='json'
   with open_source(root,s) as f:_,row,_,_=next(json_values(f))
  elif re.search(rb'<(?:\w+:)?Event(?:\s|>)',sample):
   fmt='xml';m=re.search(rb'<Event(?:\s[^>]*|)>.*?</Event>',sample,re.S)
   row=xml_row(m.group()) if m else {}
  else:
   text=sample.decode('utf-8-sig');dialect=csv.Sniffer().sniff(text[:8000],delimiters=',\t;')
   reader=csv.DictReader(io.StringIO(text),dialect=dialect);row=next(reader);fmt='csv';s={**s,'delimiter':dialect.delimiter}
 except (ValueError,UnicodeError,StopIteration,csv.Error,ET.ParseError):row=None
 kind=schema(row) if row else 'unknown'
 role='reference' if kind in ('metadata','artifact_manifest','derived_alerts','defense_actions','defense_results','defense_policy') else 'label' if kind in ('physical_labels','id_labels','aggregate_labels') else 'ground_truth' if kind=='story_gt' else 'data' if kind!='unknown' else 'unsupported'
 return {**s,'role':role,'format':fmt,'schema':kind,'columns':list(row)[:100] if isinstance(row,dict) else [],
  'sample_sha256':hashlib.sha256(sample).hexdigest(),'sample':row if isinstance(row,dict) else None,'reason':'content signature '+kind}

def records(root,s):
 with open_source(root,s) as f:
  if s['format']=='json':yield from json_values(f)
  elif s['format']=='csv':
   reader=csv.DictReader(io.TextIOWrapper(f,encoding='utf-8-sig',newline=''),delimiter=s.get('delimiter',','))
   for i,r in enumerate(reader,2):
    if None in r or any(v is None for v in r.values()):raise ValueError('Malformed CSV row '+str(i))
    yield i,r,{'row':i},orjson.dumps(r,option=orjson.OPT_SORT_KEYS)
  elif s['format']=='xml':
   buf=b'';offset=0;i=0
   while True:
    chunk=f.read(65536);buf+=chunk
    while True:
     m=re.search(rb'<Event(?:\s[^>]*|)>.*?</Event>',buf,re.S)
     if not m:break
     raw=m.group();i+=1;yield i,xml_row(raw),{'offset':offset+m.start(),'length':len(raw)},raw
     offset+=m.end();buf=buf[m.end():]
    if not chunk:break
    if len(buf)>64*1024**2:raise ValueError('XML event larger than 64 MiB')
   if re.search(rb'<Event(?:\s|>)',buf):raise ValueError('Truncated XML event')
  elif s['format']=='text':
   offset=0
   for i,line in enumerate(f,1):
    raw=line.rstrip(b'\r\n');pos=offset;offset+=len(line)
    if raw:yield i,{'raw_text':raw.decode('utf-8','replace')},{'offset':pos,'length':len(raw)},raw
  elif s['format']=='pcap':yield from packets(f)
  else:raise ValueError('Unsupported stream format '+s['format'])

def packet_fields(raw,link):
 pos=0
 if link==1:
  if len(raw)<14:raise ValueError('Short Ethernet frame')
  eth=struct.unpack('!H',raw[12:14])[0];pos=14
  while eth in (0x8100,0x88a8):eth=struct.unpack('!H',raw[pos+2:pos+4])[0];pos+=4
 elif link in (101,228,229):eth=0x86dd if raw and raw[0]>>4==6 else 0x800
 elif link==113:eth=struct.unpack('!H',raw[14:16])[0];pos=16
 else:return {'native_type':'packet:link'+str(link),'unmapped_reason':'unsupported datalink'}
 if eth==0x800:
  h=raw[pos:];ihl=(h[0]&15)*4
  if len(h)<20 or ihl<20:raise ValueError('Short IPv4 header')
  src=socket.inet_ntop(socket.AF_INET,h[12:16]);dst=socket.inet_ntop(socket.AF_INET,h[16:20]);proto=h[9]
  fragment=struct.unpack('!H',h[6:8])[0]&0x1fff;pos+=ihl
 elif eth==0x86dd:
  h=raw[pos:]
  if len(h)<40:raise ValueError('Short IPv6 header')
  src=socket.inet_ntop(socket.AF_INET6,h[8:24]);dst=socket.inet_ntop(socket.AF_INET6,h[24:40]);proto=h[6];pos+=40;fragment=0
  # Extension headers are not assumed to be TCP/UDP ports.
 else:return {'native_type':'packet:ethertype'+hex(eth),'unmapped_reason':'non-IP frame'}
 sport=dport=None
 if proto in (6,17) and not fragment and len(raw)>=pos+4:sport,dport=struct.unpack('!HH',raw[pos:pos+4])
 flags=raw[pos+13] if proto==6 and not fragment and len(raw)>=pos+14 else None
 return {'native_type':'packet:'+str(proto),'src_ip':src,'dst_ip':dst,'src_port':sport,'dst_port':dport,'protocol':str(proto),'tcp_flags':flags,
  'source':src,'target':dst,'source_type':'network_endpoint','target_type':'network_endpoint','operation':'communicate'}

def packets(f):
 magic=f.read(4);i=0
 if magic==b'\x0a\x0d\x0d\x0a':
  first=magic+f.read(8)
  if len(first)<12:raise ValueError('Truncated PCAPNG section')
  endian='<' if first[8:12]==b'\x4d\x3c\x2b\x1a' else '>' if first[8:12]==b'\x1a\x2b\x3c\x4d' else None
  if not endian:raise ValueError('Invalid PCAPNG byte order')
  n=struct.unpack(endian+'I',first[4:8])[0]
  tail=f.read(n-12)
  if n<28 or len(tail)!=n-12 or struct.unpack(endian+'I',tail[-4:])[0]!=n:raise ValueError('Malformed section')
  offset=n;interfaces=[]
  while True:
   head=f.read(8)
   if not head:break
   if len(head)!=8:raise ValueError('Truncated block header')
   typ,size=struct.unpack(endian+'II',head)
   if size<12 or size>64*1024**2:raise ValueError('Invalid PCAPNG block size')
   body=f.read(size-8)
   if len(body)!=size-8 or struct.unpack(endian+'I',body[-4:])[0]!=size:raise ValueError('Truncated PCAPNG block')
   if typ==0x0a0d0d0a:raise ValueError('Multiple PCAPNG sections require separate adapter; not silently merged')
   if typ==1:
    link=struct.unpack(endian+'H',body[:2])[0];resolution=1e-6;off=8
    while off+4<=len(body)-4:
     code,length=struct.unpack(endian+'HH',body[off:off+4]);v=body[off+4:off+4+length];off+=4+((length+3)//4)*4
     if code==0:break
     if code==9 and v:resolution=(2 if v[0]&128 else 10)**(-(v[0]&127))
    interfaces.append((link,resolution))
   elif typ==6:
    interface,hi,lo,cap,wire=struct.unpack(endian+'IIIII',body[:20]);link,res=interfaces[interface];buf=body[20:20+cap]
    if len(buf)!=cap:raise ValueError('Short enhanced packet')
    i+=1;yield i,{**packet_fields(buf,link),'timestamp':((hi<<32)|lo)*res,'captured_bytes':cap,'wire_bytes':wire},{'offset':offset,'length':size,'packet':i},head+body
   elif typ in (2,3):raise ValueError('Obsolete/simple PCAPNG packet block is unsupported; timestamps cannot be assumed')
   offset+=size
 else:
  opts={b'\xd4\xc3\xb2\xa1':('<',1e-6),b'\xa1\xb2\xc3\xd4':('>',1e-6),b'\x4d\x3c\xb2\xa1':('<',1e-9),b'\xa1\xb2\x3c\x4d':('>',1e-9)}
  endian,res=opts[magic];header=f.read(20)
  if len(header)!=20:raise ValueError('Truncated PCAP header')
  link=struct.unpack(endian+'I',header[-4:])[0];offset=24
  while True:
   head=f.read(16)
   if not head:break
   if len(head)!=16:raise ValueError('Truncated packet header')
   sec,frac,cap,wire=struct.unpack(endian+'IIII',head)
   if cap>64*1024**2:raise ValueError('Invalid capture length')
   buf=f.read(cap)
   if len(buf)!=cap:raise ValueError('Truncated packet body')
   i+=1;yield i,{**packet_fields(buf,link),'timestamp':sec+frac*res,'captured_bytes':cap,'wire_bytes':wire},{'offset':offset,'length':16+cap,'packet':i},head+buf
   offset+=16+cap

def path_value(row,path):
 if isinstance(row,dict) and path in row:return row[path]
 head,sep,tail=path.partition('.')
 if isinstance(row,dict):value=row.get(head)
 elif isinstance(row,list) and head.isdigit() and int(head)<len(row):value=row[int(head)]
 else:return None
 return path_value(value,tail) if sep else value

def normalize(row,kind,source,entities=None,mapping=None,constants=None):
 """Only observed fields, no name-based attack attribution."""
 if mapping:
  row={dest:path_value(row,src) for dest,src in mapping.items()};kind='canonical'
 if constants:row={**row,**constants}
 if kind=='standard' or 'subject_id' in row:
  row={**row,'record_id':row.get('event_id'),'timestamp':row.get('event_time'),'source':row.get('subject_id'),'source_type':row.get('subject_type'),'target':row.get('object_id'),'target_type':row.get('object_type')};kind='canonical'
 row=flatten_windows(row);c=columns(row);e={'native_type':kind,'label_raw':pick(c,'label','class','vertex_label'),
  'timestamp':pick(c,'timestamp','UtcTime','ts','starttime'),'host':pick(c,'host','hostname','Computer'),
  'native_id':pick(c,'record_id','event_uuid'),'source':None,'target':None,'operation':None,
  'command':pick(c,'command','CommandLine'),'target_path':pick(c,'target_path','path'),
  'instance_id':pick(c,'instance_id','attack_chain','scenario_id'),'step_id':pick(c,'step_id','storyline_id')}
 if kind=='cdm':
  tag,o=next(iter(row['datum'].items()));typ=tag.rsplit('.',1)[-1]
  if typ!='Event':return {'entity':True,'kind':typ,'native':o}
  a=unwrap(o.get('subject'));b=unwrap(o.get('predicateObject'));host=o.get('hostId');ak,bk=(entities or {}).get(a),(entities or {}).get(b)
  def meta(v):return v if isinstance(v,dict) else {'kind':v}
  ak,bk=meta(ak),meta(bk);op=CDM_OPS.get(o.get('type'));name=unwrap(o.get('name'))
  if o.get('type')=='EVENT_MMAP':op={'mmap':'map','munmap':'unmap'}.get(name)
  e.update(native_id=o.get('uuid'),host=host,native_type=o.get('type'),timestamp=o.get('timestampNanos'),source=a,target=b,
   source_type=NODEMAP.get(ak.get('kind')),target_type=NODEMAP.get(bk.get('kind')),operation=op,
   command=(unwrap(o.get('properties')) or {}).get('cmdLine'),target_path=bk.get('path'),actor_uuid=a)
 elif kind=='windows':
  eid=str(row.get('EventID'));sysmon=('sysmon' in str(row.get('ProviderName','')).lower() or 'sysmon' in str(row.get('Channel','')).lower() or 'ProcessGuid' in row)
  e.update(native_id=pick(c,'EventRecordID'),native_type=('sysmon:' if sysmon else 'windows:')+eid,
   identity_namespace=str(row.get('Channel',row.get('ProviderName',source))),source=pick(c,'ProcessGuid','SourceProcessGUID','ProcessId'),source_type='process')
  specs={'1':('spawn','process','ProcessGuid'),'3':('connect','network_endpoint','DestinationIp'),'5':('terminate','process','ProcessGuid'),'7':('load','module','ImageLoaded'),'8':('create_remote','thread','NewThreadId'),'10':('access','process','TargetProcessGUID'),'11':('create','file','TargetFilename'),'12':('create','registry','TargetObject'),'13':('modify','registry','TargetObject'),'14':('rename','registry','TargetObject'),'22':('query','domain','QueryName'),'23':('delete','file','TargetFilename'),'26':('delete','file','TargetFilename')}
  if sysmon and eid in specs:
   op,t,k=specs[eid];e.update(operation=op,target_type=t,target=row.get(k),target_path=row.get(k) if t in ('file','registry') else None)
   if eid=='1':e['source']=pick(c,'ParentProcessGuid','ParentProcessId');e['rule_operation']='execute'
  elif eid=='4688':e.update(operation='spawn',source=pick(c,'CreatorProcessId','ProcessId'),target=row.get('NewProcessId'),target_type='process',rule_operation='execute')
  elif eid=='5156':e.update(operation='connect',source=pick(c,'ProcessID','ProcessId','Application'),target=pick(c,'DestAddress','DestinationAddress'),target_type='network_endpoint')
  elif eid in ('4624','4634'):e.update(source=pick(c,'TargetUserSid','TargetUserName'),source_type='account',operation='login' if eid=='4624' else 'logout',target=row.get('TargetLogonId'),target_type='session')
 elif kind=='ecar':
  props=row.get('properties') or {};typ=str(row.get('object'));action=str(row.get('action','')).lower()
  e.update(native_id=row.get('id'),native_type='ecar:'+typ+':'+action,timestamp=row.get('timestamp_ms',row.get('timestamp')),source=row.get('actorID') or row.get('pid'),target=row.get('objectID'),source_type='process',operation=action,
   target_type={'FILE':'file','PROCESS':'process','REGISTRY':'registry','MODULE':'module','FLOW':'network_endpoint'}.get(typ),command=props.get('command_line'),target_path=props.get('file_path') or props.get('registry_key'))
  if typ=='PROCESS' and action=='create':e.update(source=row.get('actorID') or row.get('ppid'),operation='spawn',rule_operation='execute')
  elif typ=='FLOW':
   e.update(operation='connect',target=props.get('dst_ip'))
   if not e['source']:e.update(source=props.get('src_ip'),source_type='network_endpoint',operation='communicate')
  elif typ=='MODULE':e['operation']='load'
  elif typ=='USER_SESSION':e.update(source=row.get('principal'),source_type='account',target_type='session')
  elif typ=='THREAD' and action=='remote_create':e.update(operation='create_remote',target_type='thread')
 elif kind in ('flow','zeek','packet'):
  src=pick(c,'src_ip','Source IP','Src IP','srcaddr','id.orig_h','source');dst=pick(c,'dst_ip','Destination IP','Dst IP','dstaddr','id.resp_h','target')
  e.update(native_id=pick(c,'Flow ID','record_id'),native_type=kind+':'+str(pick(c,'Protocol','proto') or row.get('native_type','unknown')),
   source=src,target=dst,source_type='network_endpoint',target_type='network_endpoint',operation='communicate',
   src_ip=src,dst_ip=dst,src_port=pick(c,'src_port','Source Port','Src Port','id.orig_p'),dst_port=pick(c,'dst_port','Destination Port','Dst Port','id.resp_p'),protocol=pick(c,'Protocol','proto'))
  # CICFlowMeter Flow ID is generally a reusable 5-tuple, NOT a unique event identity.
  if kind=='flow':e['native_id']=pick(c,'record_id','event_uuid')
  if kind=='zeek' and row.get('query'):e.update(operation='query',target=row['query'],target_type='domain')
  if kind=='packet':e.update({k:row[k] for k in ('captured_bytes','wire_bytes','tcp_flags') if row.get(k) is not None})
 elif kind=='etw':
  name=str(row.get('EventName'));group,_,op=name.partition('/');ops={'Read':'read','Write':'write','Create':'create','Delete':'delete','Rename':'rename','Start':'spawn','Send':'send','Recv':'receive'}
  e.update(native_type='etw:'+name,source=row.get('PID'),source_type='process',target=row.get('FileName') or row.get('daddr'),
   target_type='file' if group=='FileIO' else 'network_endpoint' if group in ('TcpIp','UdpIp') else None,operation=ops.get(op),target_path=row.get('FileName'),timestamp=row.get('MSec'))
 elif kind=='zdrz':
  op={'SetValue':'modify','CreateKey':'create','DeleteKey':'delete','DeleteValue':'delete','RenameKey':'rename','RenameValue':'rename'}.get(row.get('ZDRZ057'))
  e.update(native_type='zdrz:'+str(row.get('ZDRZ057') or 'unmapped'),source=row.get('ZDRZ007'),source_type='process',target=row.get('ZDRZ058') if op else None,
   target_type='registry' if op else None,operation=op,host=row.get('ZDRZ005'),timestamp=row.get('ZDRZ002'),label_raw=None,
   mapping_caveat='observed registry field mapping only; opaque label/other columns require explicit mapping')
 else:
  e.update({k:row[k] for k in ('native_id','record_id','native_type','source','target','source_type','target_type','operation','command','target_path','host','timestamp','instance_id','step_id') if k in row})
  e['native_id']=e.get('native_id') or row.get('record_id')
 e['triple']=[e.get('source_type'),e.get('operation'),e.get('target_type')] if e.get('source') is not None and e.get('target') is not None and all(e.get(k) for k in ('source_type','operation','target_type')) else None
 return e
