from core import *
from event_contract import build
from adversarial import check_chains,variants,defense_score as real_defense_score,metric
from test_defense_semantics import FakeReviewer

def defense_score(root,defense_dir,events):
 return real_defense_score(root,defense_dir,events,reviewer=FakeReviewer(Path(defense_dir).parent/'api'))
from quality_summary import compose
from defense_input import audit,ensure_audit
from ingest import discover
import unittest,copy

class Tests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.base=BASE/'runs'/('adversarial_tests_'+datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f'));cls.base.mkdir(parents=True)
 def events(self):
  values=[]
  for i in range(2):
   e=build({'timestamp':f'2026-10-09T00:00:0{i}Z','source':'p1' if i==0 else 'p2','source_type':'process','target':'p2' if i==0 else 'f','target_type':'process' if i==0 else 'file','operation':'spawn' if i==0 else 'read','host':'h','label':'malicious','step_ids':['s'+str(i+1)]},
      {'file':'events.jsonl','row':i+1},'a'*64)
   e['event_id']='e'+str(i+1);e['native_type']='canonical';values.append(e)
  return values
 def chain(self):
  ev=self.events();tasks=[{'scenario':'run','step_id':'s'+str(i+1),'evidence':[{'record_id':e['event_id'],'observed':e}]} for i,e in enumerate(ev)]
  response={'chains':[{'scenario':'run','state':'supported','stages':[{'step_id':'s'+str(i+1),'tactic_id':ta,'citations':[{'record_id':e['event_id'],'field':'observed.operation','value':e['operation']}]} for i,(e,ta) in enumerate(zip(ev,('TA0002','TA0007')))],'edges':[{'from_step':'s1','to_step':'s2','from_event':'e1','to_event':'e2','reason':'GT states spawned child performs the subsequent read'}]}]}
  return response,tasks,ev
 def test_linked_stages_require_local_identity_time_checks(self):
  a,t,e=self.chain();self.assertTrue(check_chains(a,t,e,['TA0002','TA0007'])[0]['confirmed'])
 def test_same_host_alone_is_not_dependency(self):
  a,t,e=self.chain();e[1]['subject_id']='different';self.assertFalse(check_chains(a,t,e,['TA0002','TA0007'])[0]['confirmed'])
 def test_reversed_time_rejected(self):
  a,t,e=self.chain();e[1]['event_time']=e[0]['event_time'];self.assertFalse(check_chains(a,t,e,['TA0002','TA0007'])[0]['confirmed'])
 def test_benign_stage_does_not_count(self):
  a,t,e=self.chain();e[1]['label']='benign';self.assertFalse(check_chains(a,t,e,['TA0002','TA0007'])[0]['confirmed'])
 def test_citation_tampering_rejected(self):
  a,t,e=self.chain();a['chains'][0]['stages'][0]['citations'][0]['value']='invented';self.assertFalse(check_chains(a,t,e,['TA0002','TA0007'])[0]['confirmed'])
 def hits(self,same=False):
  e=self.events();h=[{'status':'supported','evidence_id':x['event_id'],'parent_id':'T1059','technique_id':'T1059.001' if same or i==0 else 'T1059.004','rule_id':'r'+str(i)} for i,x in enumerate(e)];return h,e
 def test_distinct_implemented_subtechniques_count(self):
  h,e=self.hits();m,v=variants(h,e);self.assertEqual(m['value'],1);self.assertEqual(v['variant_parents'],['T1059'])
 def test_filename_change_does_not_create_variant(self):
  h,e=self.hits(True);e[0]['extensions']['target_path']='a.exe';e[1]['extensions']['target_path']='b.exe';self.assertEqual(variants(h,e)[0]['value'],0)
 def defense(self,name,outcome='failed',refs=True):
  root=self.base/name/'source';root.mkdir(parents=True);events=[]
  for i in range(2):
   row={'record_id':'x'+str(i),'action_id':'a1','source':'firewall','source_type':'service','target':'1.2.3.4','target_type':'network_endpoint','operation':'block','host':'h','timestamp':f'2026-10-09T00:00:0{i}Z'}
   if i:row['result_status']=outcome
   raw=orjson.dumps(row);path=root/('event'+str(i)+'.json');path.write_bytes(raw)
   e=build(row,{'file':path.name,'offset':0,'length':len(raw),'record_sha256':hashlib.sha256(raw).hexdigest()},sha(path));e['native_id']=row['record_id'];events.append(e)
  action={'action_id':'a1','action_type':'block_network','target':'1.2.3.4','executed':True,'execution_event_ids':['x0'] if refs else [],'result_status':outcome,'result_event_ids':['x1'] if refs else []}
  save(root/'response.json',[action]);out=self.base/name/'audit';audit(root,discover(root,{}),out)
  return root,out,events
 def test_failed_but_observable_outcome_counts(self):
  r,o,e=self.defense('failed');a5,a6,d=defense_score(r,o,e)
  self.assertEqual(a5['numerator'],1);self.assertEqual(a5['denominator'],44);self.assertEqual(a6['value'],1)
  self.assertEqual(d['actions'][0]['outcome']['observed_result'],'failed')
 def test_execution_boolean_without_event_evidence_not_accepted(self):
  r,o,e=self.defense('unlinked',refs=False);a5,a6,d=defense_score(r,o,e);self.assertEqual(a5['numerator'],0);self.assertEqual(a6['value'],0)
 def test_outcome_before_action_not_accepted(self):
  r,o,e=self.defense('badtime');e[1]['event_time']={'value':'2025-01-01T00:00:00Z','unit':'iso8601','basis':'utc'}
  self.assertEqual(defense_score(r,o,e)[1]['value'],0)
 def test_ambiguous_native_event_reference_not_accepted(self):
  r,o,e=self.defense('ambiguous');e[1]['native_id']='x0';self.assertEqual(defense_score(r,o,e)[0]['numerator'],0)
 def test_alert_only_zero_by_missing_material_policy(self):
  r=self.base/'alerts/source';r.mkdir(parents=True);save(r/'alerts.json',[{'alert_id':'a','alert':'scan','alert_reason':{},'location':{}}]);o=self.base/'alerts/out';audit(r,discover(r,{}),o)
  a5,a6,_=defense_score(r,o,[]);self.assertEqual(a5['value'],0);self.assertEqual(a6['value'],0)
 def test_tampered_defense_declaration_cannot_be_scored(self):
  r,o,e=self.defense('unsupported');items=list(lines(o/'evidence.jsonl.gz'))
  for x in items:
   if 'action_declaration' in x['categories']:x['declared_defense']['action_type']='unsupported_vendor_action'
  with gzip.open(o/'evidence.jsonl.gz','wb') as f:
   for x in items:emit(f,x)
  with self.assertRaises(ValueError):defense_score(r,o,e)
 def test_packet_features_survive_normalization(self):
  from input_adapters import normalize,packet_fields
  import struct
  ip=bytes([0x45,0,0,40,0,0,0,0,64,6,0,0,1,2,3,4,5,6,7,8]);tcp=bytearray(20);tcp[:4]=struct.pack('!HH',1234,443);tcp[13]=0x12
  row={**packet_fields(ip+tcp,101),'timestamp':1700000000,'captured_bytes':40,'wire_bytes':60};e=normalize(row,'packet','x.pcap');e['adapter']='packet'
  event=build(e,{'file':'x.pcap','packet':1},'a'*64)
  self.assertEqual(event['extensions']['captured_bytes'],40);self.assertEqual(event['extensions']['wire_bytes'],60);self.assertEqual(event['extensions']['tcp_flags'],0x12)
 def test_ecar_spawn_preserves_parent_uuid_over_pid(self):
  from input_adapters import normalize
  row={'object':'PROCESS','action':'CREATE','actorID':'parent-uuid','objectID':'child-uuid','ppid':12,'pid':13,'timestamp_ms':1}
  e=normalize(row,'ecar','events.jsonl');self.assertEqual(e['source'],'parent-uuid');self.assertEqual(e['target'],'child-uuid')
  del row['actorID'];self.assertEqual(normalize(row,'ecar','events.jsonl')['source'],12)
 def test_resume_rejects_changed_defense_reference(self):
  r,o,e=self.defense('resume');ensure_audit(r,discover(r,{}),o);save(r/'response.json',[{'action_id':'b','action_type':'block_network'}])
  with self.assertRaises(ValueError):ensure_audit(r,discover(r,{}),o)
 def test_total_fixed_weights_missing_not_renormalized(self):
  c={'input_complete':True,'metrics':{f'C{i:02}':{'value':1.} for i in range(1,8)}}
  a={'input_complete':True,'annotation_score':100,'time_score':100,'behavior_score':100}
  d={'input_complete':True,'metrics':{'A01':metric(1,'observed'),'A02':metric(1,'observed'),'A03':metric(None,'missing'),'A04':metric(None,'missing')}}
  q=compose(c,a,d);self.assertAlmostEqual(q['total_score'],87.5);self.assertEqual(q['metrics']['A03']['score'],0)
  d['input_complete']=False;self.assertIsNone(compose(c,a,d)['total_score'])

if __name__=='__main__':
 r=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests));save(Tests.base/'verification.json',{'passed':r.wasSuccessful(),'tests_run':r.testsRun});raise SystemExit(not r.wasSuccessful())
