from core import *
from authenticity_tc import score,fit,annotation_score,WEIGHTS,POLICY,PROTOCOL
from authenticity import gaussian,group_for
import unittest,math

class Tests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.out=BASE/'runs'/('authenticity_tc_tests_'+datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f'));cls.out.mkdir(parents=True)
 def fixture(self,complete=True):
  time={k:fit([0,0,0],v) for k,v in POLICY['time_scale_floors'].items()}
  ref={'protocol':PROTOCOL,'reference_name':'TEST ONLY','source_file_sha256':['reference'],'time':time,
       'behavior':{'process|read|file':fit([1,1,1],.15,.02)},'behavior_mean':{'process|read|file':1},
       'unseen_behavior':fit([0,0,0],.15,.02),'weights':WEIGHTS,'comparison_scope':'synthetic fixture, not real reference'}
  g={'id':'g','sensor':'ecar/ecar','host':'h','records':10,'timed_records':10,'valid_records':10,
     'time_features':{k:0 for k in time},'behavior_proportions':{'process|read|file':1}}
  p={'input_complete':complete,'groups':[g],'counters':{'input_records':10},'source_file_sha256':['target']}
  ann={'label_counts':{'benign':10},'assigned_label_records':10,'event_level_traceable_labels':10}
  ann['semantic_review']={'protocol':'annotation-semantics-v3-step-sampling','status':'semantic_all_reviewed','population_by_label':{'benign':10},'selected_records':10,
                          'rows':[{'record_id':str(i),'label':'benign','valid_review':True,'final_state':'supported'} for i in range(10)]}
  return p,ref,ann
 def test_total_all_three_indicators(self):
  p,r,a=self.fixture();s=score(p,r,a)
  self.assertEqual(s['annotation_score'],100);self.assertEqual(s['time_score'],100);self.assertEqual(s['behavior_score'],100);self.assertEqual(s['authenticity_total'],100)
 def test_no_labels_zero_method_evidence_not_fake_logs(self):
  p,r,a=self.fixture();s=score(p,r,{'label_counts':{'unknown':10}})
  self.assertEqual(s['annotation_score'],0);self.assertEqual(s['authenticity_total'],80)
  self.assertEqual(s['annotation_detail']['status'],'no_explicit_event_labels')
 def test_unknown_labels_are_excluded_but_traceability_is_not_semantic_support(self):
  a={'label_counts':{'malicious':2,'unknown':10000},'assigned_label_records':2,'event_level_traceable_labels':2}
  self.assertEqual(annotation_score(a)['score'],0)
 def test_traceability_counts_alone_cannot_earn_semantic_points(self):
  a={'assigned_label_records':10,'event_level_traceable_labels':8};self.assertEqual(annotation_score(a)['score'],0)
 def test_stale_annotation_counts_not_guessed(self):
  self.assertEqual(annotation_score({'label_counts':{'benign':10}})['score'],0)
 def test_zero_variance_has_explicit_broad_engineering_floor(self):
  f=fit([0,0,0],.15,.02);self.assertEqual(f['scale'],.15);self.assertEqual(f['empirical_MAD'],0)
  self.assertGreater(gaussian(.1,f['center'],f['tolerance'],f['scale']),85)
 def test_unseen_behavior_counted_not_dropped(self):
  p,r,a=self.fixture();p['groups'][0]['behavior_proportions']={'new':.1,'process|read|file':.9};s=score(p,r,a)
  self.assertTrue(s['groups'][0]['behavior_features']['new']['reference_unseen']);self.assertLess(s['behavior_score'],100);self.assertGreater(s['behavior_score'],85)
 def test_preview_never_publishes_global_score(self):
  p,r,a=self.fixture(False);s=score(p,r,a);self.assertIsNone(s['authenticity_total']);self.assertEqual(s['preview_scores']['total'],100)
 def test_mapping_coverage_disclosed_without_double_penalty(self):
  p,r,a=self.fixture();p['groups'][0]['records']=20;p['counters']['input_records']=20
  s=score(p,r,a);self.assertEqual(s['coverage']['behavior_fraction'],.5);self.assertEqual(s['authenticity_total'],100)
 def test_missing_all_times_cannot_get_a_total(self):
  p,r,a=self.fixture();p['groups'][0]['timed_records']=0;p['groups'][0]['time_features']={}
  s=score(p,r,a);self.assertIsNone(s['authenticity_total']);self.assertEqual(s['status'],'insufficient_normalized_fields')
 def test_reference_overlap_flagged(self):
  p,r,a=self.fixture();p['source_file_sha256']=['reference'];s=score(p,r,a);self.assertTrue(s['self_reference']);self.assertIn('not independent',s['score_interpretation'])
 def test_cdm_types_are_one_sensor(self):
  e={'native_format':'cdm','native_type':'EVENT_READ','host':'h','provenance':{'file':'a'},'event_time':{'basis':'utc'}}
  gid=group_for(e,{})[0];e['native_type']='EVENT_WRITE';self.assertEqual(group_for(e,{})[0],gid)
 def test_weights_sum_to_one(self):self.assertAlmostEqual(sum(WEIGHTS.values()),1)

if __name__=='__main__':
 r=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
 save(Tests.out/'verification.json',{'tests_run':r.testsRun,'passed':r.wasSuccessful(),'time':stamp(),'failures':[x[1] for x in r.failures],'errors':[x[1] for x in r.errors]})
 print('artifacts',Tests.out);raise SystemExit(0 if r.wasSuccessful() else 1)
