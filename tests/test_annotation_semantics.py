from core import *
import unittest, copy
from ingest import run as ingest
from annotation_semantics import prepare, validate, review, summarize, all_records, PROTOCOL


def verdict(task, state='supported'):
    citations=[{'record_id':task['record_id'],'field':'observed.'+key,'value':task['target']['observed'][key]}
               for key in ('operation','object_id')]
    check={'state':state,'reason':'测试判断：对应行为与所声明归属一致','citations':citations}
    return {'record_id':task['record_id'],'label_check':copy.deepcopy(check),
            'step_checks':[dict(copy.deepcopy(check),step_id=s['step_id']) for s in task['claimed_steps']]}


class FakeReviewer:
    offline=False
    def __init__(self,out,transform=None):self.out=out;self.calls=0;self.transform=transform
    def ask(self,task,instruction,payload,max_tokens):
        self.calls+=1;directory=self.out/task;directory.mkdir(parents=True,exist_ok=True)
        result={'items':[verdict(t) for t in payload['annotation_tasks']]}
        if self.transform:self.transform(result)
        save(directory/'request.json',payload);save(directory/'response.json',result)
        return result,directory


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.base=BASE/'annotation';cls.base.mkdir(parents=True)
    def fixture(self,labels=None):
        folder=self.base/self._testMethodName;root=folder/'input';root.mkdir(parents=True)
        events=[]
        for i,label in enumerate(labels or ['malicious','benign']):
            events.append({'record_id':str(i),'source':'process','source_type':'process','target':'file',
                           'target_type':'file','operation':'read','timestamp':f'2026-01-01T00:{i//60:02}:{i%60:02}Z',
                           'label':label,'host':'host','instance_id':'attack' if label=='malicious' else None,
                           'step_id':'s1' if label=='malicious' else None})
        (root/'events.jsonl').write_bytes(b'\n'.join(orjson.dumps(e) for e in events)+b'\n')
        save(root/'ground_truth.json',{'scenario_name':'attack','storyline_steps':[{'storyline_id':'s1','description':'读取指定文件'}]})
        norm=folder/'normalized';ingest(root,norm,{})
        return folder,root,norm
    def test_semantic_support_and_step_contradiction_reduce_score(self):
        folder,root,norm=self.fixture()
        def wrong_step(answer):
            for item in answer['items']:
                for check in item['step_checks']:check['state']='contradicted';check['reason']='目标对象与步骤描述矛盾'
        result=review(root,norm,folder/'review',FakeReviewer(folder/'api',wrong_step))
        self.assertEqual(result['summary']['score'],0)
        self.assertEqual(result['summary']['record_states'],{'contradicted':1,'supported':1})
    def test_perfect_traceability_without_semantic_review_earns_zero(self):
        from authenticity_tc import annotation_score
        result=annotation_score({'assigned_label_records':100,'event_level_traceable_labels':100})
        self.assertEqual(result['score'],0);self.assertEqual(result['status'],'semantic_review_not_run')
    def test_fabricated_quote_is_rejected(self):
        _,root,norm=self.fixture();tasks,_=prepare(root,norm)
        answer={'items':[verdict(t) for t in tasks]}
        answer['items'][0]['label_check']['citations'][0]['value']='fabricated'
        rows=validate(answer,tasks)
        self.assertEqual(rows[0]['final_state'],'unreviewed')
    def test_label_or_identity_only_is_not_behavioral_evidence(self):
        _,root,norm=self.fixture();tasks,_=prepare(root,norm)
        for path in ('claimed_label','observed.subject_id','observed.operation'):
            answer={'items':[verdict(t) for t in tasks]}
            answer['items'][0]['label_check']['citations']=[{'record_id':tasks[0]['record_id'],'field':path,
                'value':tasks[0]['claimed_label'] if path=='claimed_label' else tasks[0]['target']['observed'][path.split('.')[-1]]}]
            self.assertEqual(validate(answer,tasks)[0]['final_state'],'unreviewed')
    def test_missing_or_duplicate_steps_cannot_pass(self):
        _,root,norm=self.fixture();tasks,_=prepare(root,norm)
        task=next(t for t in tasks if t['claimed_steps'])
        for checks in ([],[verdict(task)['step_checks'][0]]*2):
            answer=verdict(task);answer['step_checks']=checks
            self.assertEqual(validate({'items':[answer]},[task])[0]['final_state'],'unreviewed')
    def test_context_only_citation_cannot_confirm_target(self):
        _,root,norm=self.fixture();tasks,_=prepare(root,norm)
        task=tasks[0];self.assertTrue(task['context'])
        answer=verdict(task)
        for c in answer['label_check']['citations']:c['record_id']=task['context'][0]['record_id']
        self.assertEqual(validate({'items':[answer]},[task])[0]['final_state'],'unreviewed')
    def test_insufficient_is_not_mislabeled_but_receives_no_points(self):
        folder,root,norm=self.fixture()
        def insufficient(answer):
            for item in answer['items']:item['label_check']={'state':'insufficient','reason':'缺乏用途上下文','citations':[]}
        result=review(root,norm,folder/'review',FakeReviewer(folder/'api',insufficient))
        self.assertEqual(result['summary']['score'],0)
        self.assertEqual(result['summary']['record_states'],{'insufficient':2})
    def test_offline_and_incomplete_never_call_model(self):
        folder,root,norm=self.fixture()
        for complete,offline,name in ((True,True,'offline'),(False,False,'incomplete')):
            client=FakeReviewer(folder/'api');client.offline=offline
            result=review(root,norm,folder/name,client,complete=complete)
            self.assertEqual(client.calls,0);self.assertEqual(result['summary']['score'],0)
            self.assertEqual(result['selected_records'],2)
    def test_unlabeled_data_has_no_model_calls(self):
        folder,root,norm=self.fixture(['unknown'])
        client=FakeReviewer(folder/'api');result=review(root,norm,folder/'review',client)
        self.assertEqual(result['summary']['score'],0);self.assertEqual(client.calls,0)
    def test_full_selection_is_order_independent(self):
        folder,root,norm=self.fixture(['benign']*25+['malicious']*3)
        first,counts=all_records(norm)
        path=norm/'03_events.valid.jsonl.gz';events=list(lines(path))
        with gzip.open(path,'wb') as stream:
            for e in reversed(events):emit(stream,e)
        second,_=all_records(norm)
        self.assertEqual([x['event_id'] for x in first],[x['event_id'] for x in second])
        self.assertEqual(len(first),28);self.assertEqual(counts,{'benign':25,'malicious':3})
    def test_changed_source_fails_before_model(self):
        folder,root,norm=self.fixture()
        with (root/'events.jsonl').open('ab') as f:f.write(b'\n')
        client=FakeReviewer(folder/'api')
        with self.assertRaises(ValueError):review(root,norm,folder/'review',client)
        self.assertEqual(client.calls,0)
    def test_context_requires_shared_entity_not_just_same_host(self):
        from annotation_semantics import context_records
        _,root,norm=self.fixture();events=list(lines(norm/'03_events.valid.jsonl.gz'))
        target=events[0];events[1]['subject_id']='unrelated'
        with gzip.open(norm/'03_events.valid.jsonl.gz','wb') as f:
            for e in events:emit(f,e)
        self.assertEqual(context_records(norm,[target]).get(target['event_id'],[]),[])
    def test_sample_denominator_includes_locally_rejected_records(self):
        folder,root,norm=self.fixture(['benign','conflict'])
        save(root/'ground_truth.json',{'scenario_name':'attack','storyline_steps':[]})
        norm=folder/'no_steps';ingest(root,norm,{})
        # Set the normalization output to an explicit conflicted assignment.
        path=norm/'03_events.valid.jsonl.gz';events=list(lines(path))
        events[1]['label']='conflict'
        with gzip.open(path,'wb') as f:
            for e in events:emit(f,e)
        result=review(root,norm,folder/'review',FakeReviewer(folder/'api'))
        self.assertEqual(result['summary']['score'],50)
        self.assertEqual(result['summary']['selected_records'],2)
    def test_every_step_beyond_ten_is_checked(self):
        folder,root,norm=self.fixture(['malicious']*12)
        path=root/'events.jsonl';events=[orjson.loads(x) for x in path.read_bytes().splitlines()]
        for i,e in enumerate(events):e['step_id']='s'+str(i)
        path.write_bytes(b'\n'.join(orjson.dumps(e) for e in events)+b'\n')
        save(root/'ground_truth.json',{'scenario_name':'attack','storyline_steps':[
            {'storyline_id':'s'+str(i),'description':'读取指定文件'} for i in range(13)]})
        norm=folder/'all_steps';ingest(root,norm,{})
        client=FakeReviewer(folder/'api');result=review(root,norm,folder/'review',client)
        self.assertEqual(len(result['rows']),12);self.assertEqual(len(result['steps']),13)
        self.assertEqual(result['summary']['supported'],12);self.assertEqual(result['summary']['denominator'],13)
        self.assertAlmostEqual(result['summary']['score'],1200/13)
        self.assertEqual(client.calls,3)
        self.assertEqual(next(s for s in result['steps'] if s['step_id']=='s12')['state'],'insufficient')
    def test_all_labels_without_gt_are_checked(self):
        folder,root,_=self.fixture(['benign']*25)
        save(root/'ground_truth.json',{'scenario_name':'attack','storyline_steps':[]})
        norm=folder/'all_labels';ingest(root,norm,{})
        client=FakeReviewer(folder/'api');result=review(root,norm,folder/'review',client)
        self.assertEqual(result['summary']['selected_records'],25);self.assertEqual(client.calls,7)
        self.assertEqual(result['summary']['score'],100);self.assertEqual(result['summary']['unit'],'labeled_record')
    def test_missing_event_label_does_not_skip_declared_step(self):
        folder,root,_=self.fixture(['unknown'])
        path=root/'events.jsonl';e=orjson.loads(path.read_bytes().splitlines()[0]);e.update(step_id='s1',instance_id='attack');path.write_bytes(orjson.dumps(e)+b'\n')
        norm=folder/'step_only';ingest(root,norm,{})
        client=FakeReviewer(folder/'api');result=review(root,norm,folder/'review',client)
        self.assertEqual(client.calls,1);self.assertEqual(result['summary']['score'],100)
    def test_obsolete_sampling_config_is_rejected(self):
        folder,root,norm=self.fixture()
        with self.assertRaises(ValueError):review(root,norm,folder/'review',FakeReviewer(folder/'api'),limit=10)
    def test_record_linked_to_many_steps_is_split_without_omissions(self):
        folder,root,_=self.fixture(['malicious'])
        save(root/'ground_truth.json',{'scenario_name':'attack','storyline_steps':[
            {'storyline_id':'s'+str(i),'description':'读取指定文件'} for i in range(11)]})
        norm=folder/'many_steps';ingest(root,norm,{})
        path=norm/'03_events.valid.jsonl.gz';events=list(lines(path));events[0]['step_ids']=['s'+str(i) for i in range(11)]
        with gzip.open(path,'wb') as stream:
            for e in events:emit(stream,e)
        client=FakeReviewer(folder/'api');result=review(root,norm,folder/'review',client)
        self.assertEqual(client.calls,2);self.assertEqual(len(result['rows']),1)
        self.assertEqual(len(result['rows'][0]['step_checks']),11)
        self.assertEqual(result['summary']['supported'],11);self.assertEqual(result['summary']['score'],100)
    def test_one_bad_annotation_prevents_step_confirmation(self):
        folder,root,norm=self.fixture(['malicious']*15)
        def contradict_one(answer):
            for row in answer['items']:
                if row['record_id']==last:
                    for check in row['step_checks']:check['state']='contradicted'
        selected,_=all_records(norm);last=selected[-1]['event_id']
        client=FakeReviewer(folder/'api',contradict_one);result=review(root,norm,folder/'review',client)
        self.assertEqual(len(result['rows']),15);self.assertEqual(result['steps'][0]['supported_records'],14)
        self.assertEqual(result['summary']['score'],0);self.assertEqual(client.calls,4)
    def test_reply_missing_target_rejects_batch_with_trace(self):
        folder,root,norm=self.fixture()
        result=review(root,norm,folder/'review',FakeReviewer(folder/'api',lambda a:a['items'].pop()))
        self.assertEqual(result['summary']['record_states'],{'unreviewed':2})
        self.assertTrue((folder/'api/annotation_1/local_validation.json').exists())
    def test_summarize_rejects_mismatched_count(self):
        with self.assertRaises(ValueError):summarize({'protocol':PROTOCOL,'rows':[],'selected_records':1})
    def test_changed_gt_fails_before_model(self):
        folder,root,norm=self.fixture()
        save(root/'ground_truth.json',{'scenario_name':'attack','storyline_steps':[]})
        client=FakeReviewer(folder/'api')
        with self.assertRaises(ValueError):review(root,norm,folder/'review',client)
        self.assertEqual(client.calls,0)
    def test_review_cannot_be_applied_to_other_normalized_input(self):
        from authenticity import analyze
        folder,root,norm=self.fixture()
        result=review(root,norm,folder/'review',FakeReviewer(folder/'api'))
        summary=read(norm/'summary.json');summary['changed_for_test']=True;save(norm/'summary.json',summary)
        with self.assertRaises(ValueError):analyze(norm,folder/'auth',annotation_review=result)
    def test_missing_gt_step_is_unreviewed_not_inferred(self):
        folder,root,norm=self.fixture(['malicious'])
        p=norm/'03_events.valid.jsonl.gz';events=list(lines(p));events[0]['step_ids']=['absent']
        with gzip.open(p,'wb') as f:
            for e in events:emit(f,e)
        client=FakeReviewer(folder/'api');result=review(root,norm,folder/'review',client)
        self.assertEqual(client.calls,0);self.assertEqual(result['summary']['score'],0)
        self.assertEqual(result['summary']['selected_records'],1)
