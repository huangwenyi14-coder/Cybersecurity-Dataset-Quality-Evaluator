from core import *
from defense_input import audit,categories
from ingest import discover
from pipeline import execute
import unittest

class Tests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.base=BASE/'runs'/('defense_tests_'+datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f'))
 def fixture(self,name,duplicate=False,corrupt=False,conflict=False):
  source=self.base/name/'source';source.mkdir(parents=True)
  row={'source':'p','source_type':'process','operation':'read','target':'f','target_type':'file','timestamp':'2026-10-09T00:00:00Z'}
  raw=orjson.dumps(row);(source/'events.jsonl').write_bytes(raw+b'\n')
  anchor={'relative_path':'events.jsonl','byte_offset':0,'byte_length':len(raw),'record_sha256':hashlib.sha256(raw).hexdigest(),
          'physical_record_id':'p1','record_index':0,'observed_time':row['timestamp'],'label':'benign'}
  (source/'labels.jsonl').write_bytes((orjson.dumps(anchor)+b'\n')*(2 if duplicate else 1))
  if corrupt:(source/'events.jsonl').write_bytes(raw.replace(b'"read"',b'"open"')+b'\n')
  save(source/'arbitrary_name.json',[{'alert_id':'a1','alert':'test','alert_reason':{'rules':[]},'location':{'physical_record_id':'p1','relative_path':'events.jsonl','record_index':1 if conflict else 0,'timestamp':row['timestamp']}}])
  return source,self.base/name/'out'
 def run_audit(self,name,**kw):
  source,out=self.fixture(name,**kw);return source,out,audit(source,discover(source,{}),out)
 def test_content_discovery_and_exact_link(self):
  source,out,r=self.run_audit('linked');self.assertEqual(r['counts'],{'alert':1});self.assertEqual(r['link_counts'],{'verified_physical_record':1})
  self.assertEqual(r['defense_verification_state'],'insufficient_execution_and_outcome_evidence')
  self.assertEqual(r['linked_record_labels'],{'benign':1});self.assertEqual(r['files'][0]['path'],'arbitrary_name.json')
 def test_ambiguous_anchor_not_selected(self):
  _,_,r=self.run_audit('duplicate',duplicate=True);self.assertEqual(r['link_counts'],{'ambiguous_anchor':1})
 def test_corrupted_original_not_verified(self):
  _,_,r=self.run_audit('corrupt',corrupt=True);self.assertEqual(r['link_counts'],{'verification_failed':1})
 def test_conflicting_locator_not_verified(self):
  _,_,r=self.run_audit('conflict',conflict=True);self.assertEqual(r['link_counts'],{'verification_failed':1})
 def test_filename_alone_is_not_confirmed_defense(self):
  source=self.base/'hint/source';source.mkdir(parents=True);save(source/'defense.json',{'message':'unrecognized'})
  r=audit(source,discover(source,{}),self.base/'hint/out');self.assertEqual(r['status'],'candidates_unresolved');self.assertEqual(r['counts'],{})
 def test_action_results_are_declarations_not_execution_proof(self):
  source=self.base/'action/source';source.mkdir(parents=True);save(source/'response.json',[{'action_id':'a','action_type':'isolate','executed':True,'result_status':'failed'}])
  out=self.base/'action/out';r=audit(source,discover(source,{}),out)
  self.assertEqual(r['defense_verification_state'],'pending_execution_and_outcome_verification')
  self.assertEqual(next(lines(out/'evidence.jsonl.gz'))['semantic_status'],'source_declaration_only_not_verified_execution')
 def test_limit_is_explicit(self):
  source,out=self.fixture('limit');r=audit(source,discover(source,{}),out,max_records=0)
  self.assertFalse(r['complete_selected_file_scan']);self.assertEqual(r['files'][0]['status'],'partial_scan')
 def test_folder_plan_reports_file_before_scoring(self):
  source,out=self.fixture('plan');execute(source,out,offline=True,plan_only=True)
  state=read(out/'workflow.json');self.assertIn('arbitrary_name.json',state['defense']['files'])
  self.assertFalse((out/'normalized').exists());payload=read(out/'mapping/directory_samples.json')
  self.assertEqual(next(x for x in payload['files'] if x['path']=='arbitrary_name.json')['defense_evidence']['categories'],['alert'])

if __name__=='__main__':
 r=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
 save(Tests.base/'verification.json',{'tests_run':r.testsRun,'passed':r.wasSuccessful(),'time':stamp()})
 raise SystemExit(0 if r.wasSuccessful() else 1)
