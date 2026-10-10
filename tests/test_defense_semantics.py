from core import *
from event_contract import build
from defense_input import audit
from ingest import discover
from defense_semantics import prepare, validate, catalog_entries, score
import unittest, copy


def answer_for(task,mid='M1037',outcome_state='supported'):
    execution=task['execution_evidence'];outcomes=task['outcome_evidence']
    citations=[]
    if execution:
        e=execution[0]
        citations=[{'record_id':e['record_id'],'field':'observed.'+key,'value':e['observed'][key]} for key in ('operation','object_id')]
    execution_check={'state':'supported' if execution else 'insufficient','reason':'测试：防御服务确有执行行为','citations':citations}
    refs=copy.deepcopy(citations)
    if outcomes:
        e=outcomes[0];refs.append({'record_id':e['record_id'],'field':'raw.result_status','value':e['raw']['result_status']})
    return {'action_id':task['action_id'],'execution':execution_check,
            'mitigations':[{'mitigation_id':mid,'reason':'测试：执行行为符合该措施','citations':copy.deepcopy(citations)}],
            'outcome':{'state':outcome_state if outcomes else 'insufficient','observed_result':outcomes[0]['raw']['result_status'] if outcomes else 'unknown',
                       'reason':'测试：结果对应当前执行，失败也可核查','citations':refs}}


class FakeReviewer:
    offline=False
    def __init__(self,path,mid='M1037',transform=None):self.path=path;self.mid=mid;self.transform=transform;self.calls=0
    def ask(self,task,instruction,payload,max_tokens):
        self.calls+=1;out=self.path/task;out.mkdir(parents=True,exist_ok=True)
        answer={'actions':[answer_for(t,self.mid) for t in payload['defense_tasks']]}
        if self.transform:self.transform(answer)
        save(out/'request.json',payload);save(out/'response.json',answer)
        return answer,out


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.base=BASE/'defense_semantics';cls.base.mkdir(parents=True)
    def fixture(self,count=1,action_type='block_network',operation='block',result='failed'):
        folder=self.base/self._testMethodName;root=folder/'source';root.mkdir(parents=True);events=[];actions=[]
        for n in range(count):
            aid='a'+str(n);target='target'+str(n)
            for i in range(2):
                row={'record_id':aid+'e'+str(i),'action_id':aid,'source':'defender','source_type':'service',
                     'target':target,'target_type':'network_endpoint','operation':operation,'host':'h',
                     'timestamp':f'2026-01-01T00:00:0{i}Z'}
                if i:row['result_status']=result
                if action_type=='vendor_patch_rollout':row['command']='package-manager install security-update'
                path=root/(row['record_id']+'.json');raw=orjson.dumps(row);path.write_bytes(raw)
                e=build(row,{'file':path.name,'offset':0,'length':len(raw),'record_sha256':hashlib.sha256(raw).hexdigest()},sha(path))
                e['native_id']=row['record_id'];events.append(e)
            actions.append({'action_id':aid,'action_type':action_type,'target':target,'execution_event_ids':[aid+'e0'],
                            'result_status':result,'result_event_ids':[aid+'e1']})
        save(root/'response.json',actions);defense=folder/'audit';audit(root,discover(root,{}),defense)
        return folder,root,defense,events
    def test_failed_result_can_be_semantically_verifiable(self):
        folder,root,audit_dir,events=self.fixture()
        a3,a4,detail=score(root,audit_dir,events,folder/'score',FakeReviewer(folder/'api'))
        self.assertEqual(a3['numerator'],1);self.assertEqual(a3['denominator'],44);self.assertEqual(a4['value'],1)
        self.assertEqual(detail['actions'][0]['outcome']['observed_result'],'failed')
    def test_full_catalog_supports_action_outside_old_six_rules(self):
        folder,root,audit_dir,events=self.fixture(action_type='vendor_patch_rollout',operation='modify',result='success')
        a3,a4,detail=score(root,audit_dir,events,folder/'score',FakeReviewer(folder/'api',mid='M1051'))
        self.assertEqual(detail['mitigations'],['M1051']);self.assertEqual(a4['value'],1)
        self.assertEqual(len(catalog_entries()),44)
    def test_offline_never_grants_old_rule_points(self):
        folder,root,audit_dir,events=self.fixture();client=FakeReviewer(folder/'api');client.offline=True
        a3,a4,_=score(root,audit_dir,events,folder/'score',client)
        self.assertEqual(a3['value'],0);self.assertEqual(a4['value'],0);self.assertEqual(client.calls,0)
    def test_semantic_contradiction_does_not_earn_outcome_points(self):
        folder,root,audit_dir,events=self.fixture()
        def contradict(a):a['actions'][0]['outcome']['state']='contradicted'
        a3,a4,_=score(root,audit_dir,events,folder/'score',FakeReviewer(folder/'api',transform=contradict))
        self.assertEqual(a3['numerator'],1);self.assertEqual(a4['value'],0)
    def test_wrong_mitigation_id_and_do_not_mitigate_rejected(self):
        folder,root,audit_dir,events=self.fixture();tasks,_=prepare(root,audit_dir,events)
        for mid in ('M9999','M1055'):
            r=validate({'actions':[answer_for(tasks[0],mid)]},tasks,catalog_entries())[0]
            self.assertEqual(r['confirmed_mitigations'],[]);self.assertTrue(r['mapping_errors'])
    def test_fabricated_execution_quote_rejected(self):
        folder,root,audit_dir,events=self.fixture();tasks,_=prepare(root,audit_dir,events)
        answer=answer_for(tasks[0]);answer['execution']['citations'][0]['value']='invented'
        row=validate({'actions':[answer]},tasks,catalog_entries())[0]
        self.assertFalse(row['executed_supported']);self.assertFalse(row['outcome_supported']);self.assertFalse(row['confirmed_mitigations'])
    def test_result_requires_raw_result_citation(self):
        folder,root,audit_dir,events=self.fixture();tasks,_=prepare(root,audit_dir,events)
        answer=answer_for(tasks[0]);answer['outcome']['citations']=answer['execution']['citations']
        self.assertFalse(validate({'actions':[answer]},tasks,catalog_entries())[0]['outcome_supported'])
    def test_result_from_wrong_action_or_earlier_time_is_rejected(self):
        folder,root,audit_dir,events=self.fixture()
        events[1]['event_time']={'value':'2025-01-01T00:00:00Z','unit':'iso8601','basis':'utc'}
        a3,a4,_=score(root,audit_dir,events,folder/'score',FakeReviewer(folder/'api'))
        self.assertEqual(a3['numerator'],1);self.assertEqual(a4['value'],0)
    def test_all_actions_beyond_old_forty_limit_are_reviewed(self):
        folder,root,audit_dir,events=self.fixture(count=45);client=FakeReviewer(folder/'api')
        a3,a4,detail=score(root,audit_dir,events,folder/'score',client)
        self.assertEqual(a4['value'],1);self.assertEqual(a4['denominator'],45)
        self.assertEqual(detail['scope']['unselected_actions'],0);self.assertEqual(len(detail['actions']),45)
        self.assertEqual(client.calls,12)
    def test_obsolete_action_cap_is_rejected(self):
        folder,root,audit_dir,events=self.fixture()
        with self.assertRaises(ValueError):score(root,audit_dir,events,folder/'score',FakeReviewer(folder/'api'),limit=1)
    def test_action_after_old_limit_can_reduce_score(self):
        folder,root,audit_dir,events=self.fixture(count=45)
        def contradict(answer):
            for row in answer['actions']:
                if row['action_id']=='a44':row['outcome']['state']='contradicted'
        _,a4,detail=score(root,audit_dir,events,folder/'score',FakeReviewer(folder/'api',transform=contradict))
        self.assertEqual(a4['numerator'],44);self.assertEqual(a4['denominator'],45)
        self.assertIn('a44',detail['scope']['unverified_outcome_action_ids'])
    def test_incomplete_defense_scan_has_no_outcome_ratio(self):
        folder,root,audit_dir,events=self.fixture();inv=read(audit_dir/'inventory.json');inv['complete_selected_file_scan']=False;save(audit_dir/'inventory.json',inv)
        _,a4,_=score(root,audit_dir,events,folder/'score',FakeReviewer(folder/'api'))
        self.assertIsNone(a4['value']);self.assertEqual(a4['lower'],0)
    def test_incomplete_reply_is_preserved_without_points(self):
        folder,root,audit_dir,events=self.fixture()
        a3,a4,_=score(root,audit_dir,events,folder/'score',FakeReviewer(folder/'api',transform=lambda a:a['actions'].clear()))
        self.assertEqual(a3['value'],0);self.assertEqual(a4['value'],0)
        self.assertTrue((folder/'api/defense_semantic_1/local_validation.json').exists())
    def test_model_cannot_call_explicit_failure_a_success(self):
        folder,root,audit_dir,events=self.fixture();tasks,_=prepare(root,audit_dir,events)
        answer=answer_for(tasks[0]);answer['outcome']['observed_result']='success'
        self.assertFalse(validate({'actions':[answer]},tasks,catalog_entries())[0]['outcome_supported'])
    def test_fourth_result_claim_is_not_silently_discarded(self):
        folder,root,audit_dir,events=self.fixture();claims=read(root/'response.json')
        for i in range(3):
            claims.append({'action_id':'a0','result_status':'success' if i==2 else 'failed','result_event_ids':['a0e1']})
        save(root/'response.json',claims);audit_dir=folder/'updated_audit';audit(root,discover(root,{}),audit_dir)
        tasks,_=prepare(root,audit_dir,events)
        self.assertEqual(len(tasks[0]['declared_results']),4)
        row=validate({'actions':[answer_for(tasks[0])]},tasks,catalog_entries())[0]
        self.assertFalse(row['outcome_supported'])
    def test_end_to_end_defense_online_branch(self):
        from unittest.mock import patch
        from pipeline import execute
        import io
        folder,root,_,_=self.fixture()
        def respond(request,timeout):
            body=json.loads(request.data);payload=json.loads(body['messages'][1]['content'])
            self.assertIn('defense_tasks',payload)
            response={'choices':[{'finish_reason':'stop','message':{'content':json.dumps({'actions':[answer_for(t) for t in payload['defense_tasks']]})}}],
                      'usage':{'prompt_tokens':10,'completion_tokens':10,'total_tokens':20}}
            return io.BytesIO(json.dumps(response).encode())
        with patch.dict(os.environ,{'AI_BASE_URL':'https://compatible.invalid/v1','AI_MODEL':'test-chat','AI_API_KEY':'private-test-key'},clear=True),patch('ai_transport.send_request',side_effect=respond) as network:
            execute(root,folder/'pipeline',config={})
        public=read(folder/'pipeline/quality_score.json')
        self.assertEqual(network.call_count,1)
        self.assertEqual(public['metrics']['A03']['numerator'],1)
        self.assertEqual(public['metrics']['A04']['score'],100)
