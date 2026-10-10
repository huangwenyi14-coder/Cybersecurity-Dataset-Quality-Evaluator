from core import *
from ai_mapping import compile_plan,trial,at
from ai_steps import validate
from archive_input import materialize
from pipeline import execute
import unittest,tarfile,io

class Tests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.base=BASE/'runs'/('ai_pipeline_tests_'+datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f'));cls.base.mkdir(parents=True)
 def sample(self):
  return {'profiles':[{'id':'P1','format':'json','schema':'unknown','detected_role':'unsupported','files':['a.jsonl'],'samples':[{'id':'S1','file':'a.jsonl','row':{'t':'2026-10-09T00:00:00Z','actor':'p1','obj':'/tmp/a','action':'read'}}]}]}
 def proposal(self):
  return {'profiles':[{'id':'P1','role':'data','decision':'mapping','fields':{'timestamp':'t','source':'actor','target':'obj','operation':'action'},'constants':{'source_type':'process','target_type':'file'},'evidence_ids':['S1']}]}
 def test_valid_mapping_and_trial(self):
  cfg,errors,_=compile_plan(self.proposal(),self.sample());self.assertFalse(errors);rows,errors=trial(cfg,self.sample());self.assertFalse(errors);self.assertTrue(rows[0]['valid'])
 def test_invented_field_rejected(self):
  x=self.proposal();x['profiles'][0]['fields']['timestamp']='invented';self.assertTrue(compile_plan(x,self.sample())[1])
 def test_fabricated_identity_constant_rejected(self):
  x=self.proposal();x['profiles'][0]['constants']['source']='made-up';self.assertTrue(compile_plan(x,self.sample())[1])
 def test_evidence_reference_rejected(self):
  x=self.proposal();x['profiles'][0]['evidence_ids']=['unknown'];self.assertTrue(compile_plan(x,self.sample())[1])
 def test_trial_without_time_does_not_pass(self):
  x=self.proposal();del x['profiles'][0]['fields']['timestamp'];cfg,_,_=compile_plan(x,self.sample());self.assertTrue(trial(cfg,self.sample())[1])
 def test_cannot_hide_recognized_data(self):
  p=self.sample();p['profiles'][0]['detected_role']='data';x=self.proposal();x['profiles'][0].update(decision='retain',role='reference');self.assertTrue(compile_plan(x,p)[1])
 def test_GT_citation_validation(self):
  tasks=[{'step_id':'s1','scenario':'case','evidence':[{'record_id':'r1','observed':{'operation':'read'}}]}]
  reply={'items':[{'step_id':'s1','state':'supported','citations':[{'record_id':'r1','field':'observed.operation','value':'read'}],'missing_claims':[]}]}
  self.assertTrue(validate(reply,tasks)[0]['valid_review']);reply['items'][0]['citations'][0]['value']='write';self.assertFalse(validate(reply,tasks)[0]['valid_review'])
 def test_GT_missing_claims_prevent_full_support(self):
  tasks=[{'step_id':'s1','scenario':'case','evidence':[]}];reply={'items':[{'step_id':'s1','state':'supported','citations':[],'missing_claims':['missing']} ]};self.assertFalse(validate(reply,tasks)[0]['valid_review'])
 def test_nested_dotted_source_keys(self):
  self.assertEqual(at({'raw':{'id.resp_h':'1.2.3.4'}},'raw.id.resp_h'),'1.2.3.4')
 def test_resume_preserves_usage_without_double_count(self):
  from ai_transport import Reviewer
  root=self.base/'usage_resume';root.mkdir();save(root/'usage.json',{'calls':[{'request_sha256':'existing'}],'usage':{'prompt_tokens':12}})
  r=Reviewer(root,offline=True);self.assertEqual(r.usage['prompt_tokens'],12);self.assertEqual(len(r.calls),1)
 def test_archive_traversal_blocked(self):
  src=self.base/'unsafe';src.mkdir();out=self.base/'unsafe_out';out.mkdir()
  with tarfile.open(src/'a.tar.gz','w:gz') as z:
   member=tarfile.TarInfo('../escape');member.size=1;z.addfile(member,io.BytesIO(b'x'))
  with self.assertRaises(ValueError):materialize(src,out)
  self.assertFalse((self.base/'escape').exists())
 def test_offline_end_to_end_and_score_formula(self):
  src=self.base/'folder';src.mkdir();out=self.base/'workflow'
  (src/'records.jsonl').write_bytes(orjson.dumps({'record_id':'e1','timestamp':'2026-10-09T00:00:00Z','source':'p1','source_type':'process','operation':'read','target':'f1','target_type':'file','label':'benign'})+b'\n')
  before=sha(src/'records.jsonl');r=execute(src,out,offline=True,authenticity_config={'reference_policy':'none'})
  self.assertIsNotNone(r['score']);self.assertIn('C07',r['unknown_metrics']);self.assertEqual(before,sha(src/'records.jsonl'));self.assertTrue((out/'report.md').exists());self.assertTrue(read(out/'verification.json')['score_formula'])
  self.assertEqual(r['authenticity']['status'],'reference_unavailable');self.assertTrue(Path(r['authenticity']['report']).exists());self.assertEqual(read(out/'authenticity/verification.json')['external_calls'],0)

if __name__=='__main__':
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
 save(Tests.base/'verification.json',{'tests_run':result.testsRun,'passed':result.wasSuccessful(),'time':stamp(),'python':os.sys.executable})
 print('artifacts',str(Tests.base));raise SystemExit(0 if result.wasSuccessful() else 1)
