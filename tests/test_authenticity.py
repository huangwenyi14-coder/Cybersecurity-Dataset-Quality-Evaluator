from core import *
from authenticity import analyze,calibrate,score_profiles,gaussian,timestamp_ns,quantile,SECOND,VERSION,group_for
from event_contract import build
import unittest,math


class Tests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.root=BASE/'runs'/('authenticity_tests_'+datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f'));cls.root.mkdir(parents=True)
 def make(self,name,times,complete=True,incomplete_indices=(),hosts=None,files=None,basis='utc',behaviors=None):
  root=self.root/name;root.mkdir();valid=[];incomplete=[]
  for i,t in enumerate(times):
   e=build({'timestamp':str(t),'source_type':'process','source':'p','operation':behaviors[i] if behaviors else 'read','target_type':'file','target':'f','host':hosts[i] if hosts else 'h','native_type':'ecar:FILE:read'},
           {'file':files[i] if files else 'events.jsonl','row':i+1},hashlib.sha256(name.encode()).hexdigest(),{'time_unit':'s','time_basis':basis})
   e['native_format']='ecar';e['label']='benign';e['label_evidence']=[]
   if i in incomplete_indices:e['object_id']=None;incomplete.append(e)
   else:valid.append(e)
  for fname,events in [('03_events.valid.jsonl.gz',valid),('03_events.incomplete.jsonl.gz',incomplete)]:
   with gzip.open(root/fname,'wb') as f:
    for e in events:emit(f,e)
  save(root/'summary.json',{'complete_input_scan':complete,'counts':{'records':len(times),'valid_records':len(valid),'incomplete_records':len(incomplete)},'files':[{'path':'events','sha256':hashlib.sha256(name.encode()).hexdigest()}]})
  return root
 def run_case(self,name,times,config=None,**kwargs):
  root=self.make(name,times,**kwargs);return analyze(root,self.root/(name+'_out'),{'reference_policy':'none',**(config or {})})
 def test_plateau_and_slow_gaussian(self):
  self.assertEqual(gaussian(12,10,2,2),100);self.assertAlmostEqual(gaussian(13,10,2,2),88.24969025845955)
  self.assertGreater(gaussian(14,10,2,2),gaussian(15,10,2,2))
  with self.assertRaises(ValueError):gaussian(1,0,0,0)
 def test_units_and_clock_basis(self):
  self.assertEqual(timestamp_ns({'value':'1000','unit':'ms','basis':'utc'}),SECOND)
  self.assertEqual(timestamp_ns({'value':'-0.1','unit':'s','basis':'relative'}),-100000000)
  self.assertIsNone(timestamp_ns({'value':'2026-10-09T00:00:00','unit':'iso8601','basis':'utc'}))
 def test_sparse_zero_windows_and_burst_counts(self):
  p,s=self.run_case('sparse',[0,0,2,10]);g=p['groups'][0];w=g['windows']['1']
  self.assertEqual(w['count_distribution']['n'],11);self.assertAlmostEqual(w['zero_window_fraction'],8/11)
  self.assertAlmostEqual(w['duration_weighted_mean_eps'],4/11);self.assertEqual(w['count_distribution']['max'],2)
  self.assertIsNone(s['time_score']);self.assertEqual(s['status'],'reference_unavailable')
 def test_incomplete_behavior_still_contributes_time(self):
  p,s=self.run_case('incomplete',[0,1,2],incomplete_indices=(1,));g=p['groups'][0]
  self.assertEqual(g['timed_records'],3);self.assertEqual(g['valid_records'],2);self.assertEqual(sum(g['behavior_counts'].values()),2)
 def test_rotated_files_merge_and_sort(self):
  p,s=self.run_case('rotated',[100,0,1,101],files=['b','a','a','b'])
  self.assertEqual(len(p['groups']),1);self.assertEqual(p['gap_candidates'],1)
  gap=next(lines(self.root/'rotated_out/gap_candidates.jsonl.gz'));self.assertEqual(gap['duration_seconds'],99);self.assertTrue(gap['not_a_confirmed_interruption'])
 def test_relative_clocks_are_isolated(self):
  p,s=self.run_case('relative',[0,100],files=['a','b'],basis='relative')
  self.assertEqual(len(p['groups']),2);self.assertEqual(p['gap_candidates'],0)
 def test_hosts_are_isolated(self):
  p,s=self.run_case('hosts',[0,100],hosts=['a','b']);self.assertEqual(len(p['groups']),2)
 def test_zeek_http_host_is_not_collection_host(self):
  e={'native_format':'zeek','native_type':'zeek:tcp','host':'website-a','provenance':{'file':'sensor/http.json'},'event_time':{'basis':'utc'}}
  first=group_for(e,{})[0];e['host']='website-b';second=group_for(e,{})[0]
  self.assertEqual(first,second);self.assertIn('http',group_for(e,{})[1]['sensor'])
 def test_behavior_windows_include_absent_categories(self):
  p,s=self.run_case('behaviors',[0,60,120],behaviors=['read','write','write'])
  d=read(self.root/'behaviors_out/behavior_distribution.json')[0];r=next(x for x in d['behaviors'] if '|read|' in x['behavior'])
  self.assertEqual(r['window_60s_proportion']['p50'],0);self.assertAlmostEqual(r['proportion'],1/3)
 def test_long_span_uses_compressed_zeros(self):
  p,s=self.run_case('long',[0,1000000000]);rows=list(lines(self.root/'long_out/time_windows.jsonl.gz'))
  self.assertLess(len(rows),15);self.assertEqual(p['groups'][0]['windows']['1']['count_distribution']['n'],1000000001)
 def test_negative_seconds_bucket_floor(self):
  p,s=self.run_case('negative',[-11,-1,0],basis='relative');rows=[x for x in lines(self.root/'negative_out/time_windows.jsonl.gz') if x['window_seconds']==10 and x['count']]
  self.assertEqual([x['first_bucket'] for x in rows],[-2,-1,0])
 def test_capture_bounds_require_evidence(self):
  root=self.make('capture',[1,2]);p,s=analyze(root,self.root/'capture_first');gid=p['groups'][0]['id']
  with self.assertRaises(ValueError):analyze(root,self.root/'capture_bad',{'capture_intervals':{gid:{'start_second':0,'end_second':5}}})
  p,s=analyze(root,self.root/'capture_good',{'capture_intervals':{gid:{'start_second':0,'end_second':5,'evidence':'test capture start/stop manifest'}}})
  self.assertAlmostEqual(p['groups'][0]['windows']['1']['zero_window_fraction'],3/5)
 def test_preview_cannot_calibrate(self):
  p,s=self.run_case('preview',[0,1],complete=False,config={'comparison_context':'test'})
  with self.assertRaises(ValueError):calibrate([self.root/'preview_out/features.json'],self.root/'preview_reference.json',{'kind':'test_fixture','evidence':'test'})
 def test_reference_fit_and_self_comparison_block(self):
  paths=[]
  for i in range(3):
   p,s=self.run_case('ref'+str(i),[0,1+i,6+i],config={'comparison_context':'fixture-v1'},behaviors=['read']*(i+1)+['write']*(2-i))
   paths.append(self.root/('ref'+str(i)+'_out/features.json'))
  ref=calibrate(paths,self.root/'test_reference.json',{'kind':'test_fixture','evidence':'synthetic test only'})
  with self.assertRaises(ValueError):score_profiles(p,ref)
  target,s=self.run_case('target',[0,2,7],config={'comparison_context':'fixture-v1'},behaviors=['read','read','write'])
  s=score_profiles(target,ref);self.assertEqual(s['status'],'test_fixture_only_not_dataset_authenticity')
  self.assertIsNotNone(s['behavior_score']);self.assertIsNone(s['authenticity_total'])
 def test_unknown_behavior_not_silently_ignored(self):
  g={'id':'g','sensor':'s','basis':'utc','comparison_context':'test','records':1,'valid_records':1,'timed_records':1,'time_features':{},'behavior_proportions':{'new':1}}
  from authenticity import reference_key
  model={'time':{},'behavior':{'old':{'status':'calibrated','center':1,'tolerance':0,'scale':.2}},'behavior_mean':{'old':1}}
  ref={'protocol':VERSION,'declaration':{'kind':'test_fixture'},'dataset_fingerprints':['other'],'source_file_sha256':[],'models':{reference_key(g):model}}
  s=score_profiles({'dataset_fingerprint':'target','source_file_sha256':[],'input_complete':True,'groups':[g]},ref)
  self.assertIsNone(s['behavior_score']);self.assertEqual(s['groups'][0]['behavior_known_weight'],.5)
 def test_calibrated_time_and_behavior_end_to_end(self):
  paths=[]
  for i,(rate,active,reads) in enumerate([(1,8,3),(2,7,7),(3,6,12)]):
   times=[s for s in list(range(active-1))+[9] for _ in range(rate)]
   name='varying_ref'+str(i)
   self.run_case(name,times,config={'comparison_context':'dense-fixture'},behaviors=['read']*reads+['write']*(len(times)-reads))
   paths.append(self.root/(name+'_out/features.json'))
  ref=calibrate(paths,self.root/'varying_reference.json',{'kind':'test_fixture','evidence':'three independent synthetic unit-test datasets, not real captures'})
  times=[s for s in list(range(6))+[9] for _ in range(2)]
  p,_=self.run_case('within_reference',times,config={'comparison_context':'dense-fixture'},behaviors=['read']*7+['write']*7)
  result=score_profiles(p,ref);self.assertAlmostEqual(result['time_score'],100);self.assertAlmostEqual(result['behavior_score'],100)
  times=[s for s in (0,9) for _ in range(20)]
  p,_=self.run_case('outside_reference',times,config={'comparison_context':'dense-fixture'},behaviors=['read']*39+['write'])
  lower=score_profiles(p,ref);self.assertLess(lower['time_score'],100);self.assertGreater(lower['time_score'],0)
  self.assertLess(lower['behavior_score'],100);self.assertGreater(lower['behavior_score'],0)
  save(self.root/'curve_demonstration.json',{'scope':'synthetic test fixtures only','within_reference':result,'outside_reference':lower})
 def test_quantiles_do_not_expand_zero_spans(self):
  self.assertEqual(quantile({0:1000000000,3:1},.95),0)
 def test_output_cannot_modify_input(self):
  root=self.make('guard',[0])
  with self.assertRaises(ValueError):analyze(root,root/'results')


if __name__=='__main__':
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
 save(Tests.root/'verification.json',{'tests_run':result.testsRun,'passed':result.wasSuccessful(),'failures':[str(x[1]) for x in result.failures],'errors':[str(x[1]) for x in result.errors],'python':os.sys.executable,'time':stamp()})
 print('artifacts',str(Tests.root));raise SystemExit(0 if result.wasSuccessful() else 1)
