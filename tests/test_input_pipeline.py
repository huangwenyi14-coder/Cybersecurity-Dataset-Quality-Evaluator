"""End-to-end fixtures under engineering output; no dataset content mutation."""
from core import *
from ingest import run,protected
from event_contract import validate,event_time
from input_adapters import json_values
from curves import technique_score
import unittest,io,struct,zipfile

class InputTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.base=BASE/'runs'/('input_tests_'+datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f'));cls.base.mkdir(parents=True)
 def folders(self):
  d=self.base/self._testMethodName;d.mkdir();src=d/'new_dataset';src.mkdir();return src,d/'output'
 def write(self,p,rows):p.write_bytes(b''.join(orjson.dumps(x)+b'\n' for x in rows))
 def event(self,**kw):return {'record_id':'event-a','timestamp':'2026-10-09T00:00:00Z','source':'p1','source_type':'process','operation':'read','target':'file1','target_type':'file',**kw}
 def test_minimum_fields_and_external_labels(self):
  src,out=self.folders();self.write(src/'unfamiliar_name.jsonl',[self.event(),self.event(record_id='event-b',target=None),self.event(record_id='event-c',operation='unknown')])
  (src/'random_annotations.csv').write_text('record_id,label,attack_chain,step_id\nevent-a,malicious,attack-one,step-one\n',encoding='utf-8')
  s=run(src,out);self.assertEqual(s['counts']['records'],3);self.assertEqual(s['counts']['valid_records'],1);self.assertEqual(s['counts']['incomplete_records'],2)
  self.assertEqual(s['labels']['malicious'],1);self.assertEqual(s['matched_label_rows'],1);self.assertEqual(s['observed_instances'],['attack-one'])
  self.assertTrue(s['historical_result_dependency'] is False)
 def test_custom_mapping_and_numeric_labels(self):
  src,out=self.folders();(src/'odd.csv').write_text('when,who,who_type,does,what,what_type,verdict\n1728432000,p1,process,READ,/tmp/a,file,1\n',encoding='utf-8')
  cfg={'files':{'*.csv':{'format':'csv','fields':{'timestamp':'when','source':'who','source_type':'who_type','operation':'does','target':'what','target_type':'what_type','label':'verdict'},'time_unit':'s','values':{'operation':{'READ':'read'}}}},'label_map':{'1':'malicious'}}
  s=run(src,out,cfg);self.assertEqual(s['counts']['valid_records'],1);self.assertEqual(s['labels']['malicious'],1)
 def test_no_numeric_label_guess(self):
  src,out=self.folders();self.write(src/'a.jsonl',[self.event(label=1)])
  s=run(src,out);self.assertEqual(s['labels']['unmapped'],1)
 def test_flow_five_tuple_not_unique_identity(self):
  src,out=self.folders();(src/'flows.csv').write_text('Flow ID,Timestamp,Source IP,Destination IP,Protocol,Flow Duration,Label\na,2026-10-09T00:00:00Z,10.0.0.1,10.0.0.2,6,20,BENIGN\na,2026-10-09T00:00:01Z,10.0.0.1,10.0.0.2,6,25,BENIGN\n',encoding='utf-8')
  s=run(src,out);self.assertEqual(s['counts']['valid_records'],2);self.assertEqual(s['counts']['unique_records'],2)
 def test_sysmon_xml(self):
  src,out=self.folders();(src/'events.xml').write_text('<Events><Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>3</EventID><EventRecordID>7</EventRecordID><Computer>host1</Computer><TimeCreated SystemTime="2026-10-09T00:00:00Z"/></System><EventData><Data Name="ProcessGuid">p1</Data><Data Name="DestinationIp">10.0.0.2</Data></EventData></Event></Events>',encoding='utf-8')
  s=run(src,out);self.assertEqual(s['counts']['valid_records'],1);self.assertIn('process|connect|network_endpoint',s['triples'])
 def test_cdm_forward_references_and_node_labels(self):
  src,out=self.folders();tag='com.bbn.tc.schema.avro.cdm18.'
  rows=[{'datum':{tag+'Event':{'uuid':'evt1','hostId':'h','timestampNanos':1728432000000000000,'type':'EVENT_READ','subject':{'uuid':'p1'},'predicateObject':{'uuid':'f1'}}}},
   {'datum':{tag+'Subject':{'uuid':'p1','hostId':'h','properties':{'map':{'path':'/bin/cat'}}}}},
   {'datum':{tag+'FileObject':{'uuid':'f1','baseObject':{'hostId':'h','properties':{'map':{'filename':'/etc/passwd'}}}}}}]
  self.write(src/'events.json',rows);(src/'labels.csv').write_text('uuid,process_name,label,attack_chain\np1,cat,attack,a1\n',encoding='utf-8')
  s=run(src,out);self.assertEqual(s['counts']['records'],1);self.assertEqual(s['counts']['valid_records'],1);self.assertEqual(s['labels']['unknown'],1);self.assertEqual(s['counts']['node_context_records'],1)
 def test_physical_groundtruth_hash_and_uncovered_bytes(self):
  src,out=self.folders();raw=orjson.dumps(self.event());(src/'data.jsonl').write_bytes(raw+b'\n'+orjson.dumps(self.event(record_id='unlabelled')))
  self.write(src/'anchors.jsonl',[{'relative_path':'data.jsonl','byte_offset':0,'byte_length':len(raw),'record_sha256':hashlib.sha256(raw).hexdigest(),'label':'malicious','source_format':'json'}])
  s=run(src,out);self.assertEqual(s['labels']['malicious'],1);self.assertTrue(s['physical_GT_uncovered_ranges']);self.assertFalse(s['complete_input_scan']);self.assertIsNone(read(out/'score.json')['confirmed_component_lower_bound'])
 def test_zip_members_and_array(self):
  src,out=self.folders()
  with zipfile.ZipFile(src/'data.zip','w') as z:z.writestr('nested/arbitrary.json',json.dumps([self.event(),self.event(record_id='b')]))
  s=run(src,out);self.assertEqual(s['counts']['valid_records'],2);self.assertTrue(s['complete_input_scan'])
 def test_pcap(self):
  src,out=self.folders();ether=b'\x00'*12+b'\x08\x00';ip=bytes.fromhex('4500001c00000000401100000a0000010a000002');udp=struct.pack('!HHHH',5000,53,8,0);packet=ether+ip+udp
  capture=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)+struct.pack('<IIII',1728432000,0,len(packet),len(packet))+packet
  (src/'packets.pcap').write_bytes(capture);s=run(src,out);self.assertEqual(s['counts']['valid_records'],1);self.assertIn('network_endpoint|communicate|network_endpoint',s['triples'])
 def test_pcapng(self):
  src,out=self.folders()
  def block(kind,body):
   size=12+len(body);return struct.pack('<II',kind,size)+body+struct.pack('<I',size)
  packet=b'\x00'*12+b'\x08\x00'+bytes.fromhex('4500001c00000000401100000a0000010a000002')+struct.pack('!HHHH',5000,53,8,0)
  section=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1));interface=block(1,struct.pack('<HHI',1,0,65535))
  epb=block(6,struct.pack('<IIIII',0,0,1000000,len(packet),len(packet))+packet+b'\0'*((-len(packet))%4))
  (src/'a.pcapng').write_bytes(section+interface+epb);s=run(src,out);self.assertEqual(s['counts']['valid_records'],1)
 def test_ambiguous_non_global_label_id_not_fanned_out(self):
  src,out=self.folders();self.write(src/'a.jsonl',[self.event(record_id='1')]);self.write(src/'b.jsonl',[self.event(record_id='1',host='other')])
  (src/'labels.csv').write_text('record_id,label\n1,malicious\n',encoding='utf-8')
  s=run(src,out);self.assertEqual(s['matched_label_rows'],0);self.assertEqual(s['labels']['unknown'],2)
 def test_contradictory_labels_are_not_accepted(self):
  src,out=self.folders();self.write(src/'a.jsonl',[self.event()]);(src/'labels.csv').write_text('record_id,label\nevent-a,malicious\nevent-a,benign\n',encoding='utf-8')
  s=run(src,out);self.assertEqual(s['labels']['conflict'],1);self.assertEqual(s['counts']['label_conflicts'],1)
 def test_unsupported_is_not_zero_quality(self):
  src,out=self.folders();self.write(src/'a.jsonl',[self.event()]);(src/'mystery.dat').write_bytes(b'not a recognized format')
  s=run(src,out);self.assertFalse(s['complete_input_scan']);self.assertIsNone(read(out/'score.json')['confirmed_component_lower_bound'])
 def test_duplicate_native_identity_conflict_visible(self):
  src,out=self.folders();self.write(src/'a.jsonl',[self.event(),self.event(target='file2')]);s=run(src,out)
  self.assertEqual(s['counts']['duplicate_identity_records'],1);self.assertEqual(s['counts']['identity_content_conflicts'],1)
 def test_schema_rejects_empty_placeholders(self):
  src,out=self.folders();self.write(src/'a.jsonl',[self.event(source=' ',target='unknown',timestamp=None)])
  s=run(src,out);self.assertEqual(s['counts']['incomplete_records'],1);self.assertIn('subject_id:missing_or_placeholder',s['missing_fields'])
 def test_incomplete_event_cannot_boost_technique_score(self):
  src,out=self.folders();self.write(src/'a.jsonl',[self.event(timestamp=None,operation='execute',command='uname -a',label='malicious')])
  run(src,out);self.assertEqual(read(out/'score.json')['confirmed_techniques'],[])
  self.assertEqual(read(out/'05_rule_hits.json')[0]['status'],'input_incomplete_candidate')
 def test_relative_timestamp_not_promoted_to_UTC(self):
  self.assertEqual(event_time('123.5','ms','relative')['basis'],'relative');self.assertIsNone(event_time('123.5'))
  self.assertEqual(event_time('2026-10-09T00:00:00.1234567Z')['raw'],'2026-10-09T00:00:00.1234567Z')
 def test_raw_input_writes_and_missing_input_blocked(self):
  src,out=self.folders()
  with self.assertRaises(ValueError):protected(src,src/'results')
  with self.assertRaises(ValueError):protected(out/'missing_input',out)
 def test_malformed_array_not_silently_accepted(self):
  for raw in (b'[{"a":1}',b'[{"a":1},]',b'[{"a":1}{"a":2}]'):
   with self.assertRaises(ValueError):list(json_values(io.BytesIO(raw)))
 def test_curve_concave_and_saturates(self):
  values=[technique_score(i) for i in range(40)];self.assertEqual(values[0],0);self.assertEqual(values[30],1)
  increments=[b-a for a,b in zip(values,values[1:])];self.assertTrue(all(a>=b-1e-12 for a,b in zip(increments,increments[1:])));self.assertAlmostEqual(values[10],5/9)

if __name__=='__main__':
 suite=unittest.defaultTestLoader.loadTestsFromTestCase(InputTests);result=unittest.TextTestRunner(verbosity=2).run(suite)
 save(InputTests.base/'verification.json',{'tests_run':result.testsRun,'passed':result.wasSuccessful(),'failures':[str(x[0]) for x in result.failures],'errors':[str(x[0]) for x in result.errors],'python':os.sys.executable,'time':stamp()})
 print('artifacts',InputTests.base)
 raise SystemExit(0 if result.wasSuccessful() else 1)
