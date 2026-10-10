"""Public interface, environment isolation, and full online-path tests without egress."""
from core import *
from metric_catalog import METRICS
from unittest.mock import patch
import io, unittest
import runtime_config
from ai_transport import Reviewer
from pipeline import execute
from quality_summary import compose

class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base=BASE/'release';cls.base.mkdir(parents=True)

    def setUp(self):
        isolated=patch.object(runtime_config,'ENV_FILE',self.base/'absent.env')
        isolated.start();self.addCleanup(isolated.stop)

    def test_ids_are_contiguous(self):
        self.assertEqual(list(METRICS),[f'C{i:02}' for i in range(1,8)]+[f'R{i:02}' for i in range(1,4)]+[f'A{i:02}' for i in range(1,5)])

    def test_env_literal_precedence_and_no_execution(self):
        p=self.base/'settings.env'
        p.write_text('DEEPSEEK_API_KEY="literal-test-value" # comment\nDEEPSEEK_MODEL=deepseek-flash\n',encoding='utf-8')
        with patch.object(runtime_config,'ENV_FILE',p),patch.dict(os.environ,{'DEEPSEEK_MODEL':'test-model'},clear=True):
            s=runtime_config.settings(require_key=True)
            self.assertEqual(s['api_key'],'literal-test-value');self.assertEqual(s['model'],'test-model')

    def test_invalid_env_does_not_echo_value(self):
        p=self.base/'bad.env';p.write_text('DEEPSEEK_API_KEY="private-value',encoding='utf-8')
        with self.assertRaises(ValueError) as caught:runtime_config.read_env(p)
        self.assertNotIn('private-value',str(caught.exception))

    def test_key_missing_rejected_without_network(self):
        with patch.object(runtime_config,'ENV_FILE',self.base/'absent'),patch.dict(os.environ,{},clear=True):
            with self.assertRaises(ValueError):runtime_config.settings(require_key=True)
            self.assertEqual(runtime_config.settings()['api_key'],'')

    def test_endpoint_cannot_leak_key_to_other_host(self):
        with patch.dict(os.environ,{'DEEPSEEK_BASE_URL':'https://unrelated.invalid'},clear=True):
            with self.assertRaises(ValueError):runtime_config.settings()

    def test_exact_request_cache_avoids_network_and_excludes_key(self):
        out=self.base/'cache'
        raw={'model':'deepseek-flash','choices':[{'finish_reason':'stop','message':{'content':'{"ok":true}'}}],
             'usage':{'prompt_tokens':10,'completion_tokens':3,'total_tokens':13}}
        with patch.dict(os.environ,{'DEEPSEEK_API_KEY':'private-test-key'},clear=True):
            with patch('ai_transport.send_request',return_value=io.BytesIO(json.dumps(raw).encode())) as call:
                r=Reviewer(out);self.assertTrue(r.ask('check','Return JSON',{},30)[0]['ok'])
                self.assertTrue(r.ask('check','Return JSON',{},30)[0]['ok']);self.assertEqual(call.call_count,1)
                body=json.loads(call.call_args.args[0].data)
                self.assertEqual(body['thinking'],{'type':'disabled'})
                self.assertEqual(body['temperature'],0)
        for p in out.rglob('*.json'):self.assertNotIn('private-test-key',p.read_text(encoding='utf-8'))

    def test_partial_authenticity_preserves_available_points(self):
        c={'input_complete':True,'metrics':{}}
        a={'input_complete':True,'annotation_score':100,'time_score':None,'behavior_score':None}
        d={'input_complete':True,'metrics':{}}
        r=compose(c,a,d)
        self.assertEqual(r['dimensions']['authenticity']['score'],20)
        self.assertEqual(r['total_score'],8)
        self.assertTrue(r['metrics']['R02']['zero_policy_applied'])

    def test_generic_profile_does_not_inherit_deepseek_credentials(self):
        env={'DEEPSEEK_API_KEY':'legacy-private','AI_BASE_URL':'https://compatible.invalid/v1','AI_MODEL':'chat'}
        with patch.dict(os.environ,env,clear=True):
            self.assertEqual(runtime_config.settings()['api_key'],'')
            with self.assertRaises(ValueError):runtime_config.settings(require_key=True)

    def test_compatible_options_and_local_keyless_endpoint(self):
        env={'AI_BASE_URL':'http://127.0.0.1:8000/v1/','AI_MODEL':'local-chat',
             'AI_JSON_MODE':'false','AI_TOKEN_PARAMETER':'max_completion_tokens'}
        raw={'choices':[{'finish_reason':'stop','message':{'content':'{"ok":true}'}}]}
        with patch.dict(os.environ,env,clear=True),patch('ai_transport.send_request',return_value=io.BytesIO(json.dumps(raw).encode())) as call:
            config=runtime_config.settings(require_key=True)
            self.assertEqual(config['base_url'],'http://127.0.0.1:8000/v1')
            Reviewer(self.base/'local-api').ask('check','Return JSON',{},30)
            req=call.call_args.args[0];body=json.loads(req.data)
            self.assertEqual(req.full_url,'http://127.0.0.1:8000/v1/chat/completions')
            self.assertFalse(req.has_header('Authorization'))
            self.assertEqual(body['max_completion_tokens'],30)
            for key in ('response_format','temperature','thinking','max_tokens'):self.assertNotIn(key,body)

    def test_cache_is_scoped_to_endpoint(self):
        env={'AI_BASE_URL':'https://first.invalid/v1','AI_MODEL':'same-model','AI_API_KEY':'private-test-key'}
        raw={'choices':[{'finish_reason':'stop','message':{'content':'{"ok":true}'}}]}
        def respond(*args,**kwargs):return io.BytesIO(json.dumps(raw).encode())
        with patch.dict(os.environ,env,clear=True),patch('ai_transport.send_request',side_effect=respond) as call:
            out=self.base/'endpoint-cache'
            Reviewer(out).ask('check','Return JSON',{},30)
            os.environ['AI_BASE_URL']='https://second.invalid/v1'
            Reviewer(out).ask('check','Return JSON',{},30)
            Reviewer(out).ask('check','Return JSON',{},30)
            self.assertEqual(call.call_count,2)
            self.assertEqual(len(list(out.glob('*/response.json'))),2)

    def test_invalid_generic_options_rejected(self):
        env={'AI_BASE_URL':'https://compatible.invalid/v1','AI_MODEL':'chat'}
        invalid={'AI_BASE_URL':['http://remote.invalid/v1','https://user:pass@host/v1','https://host/v1?key=private','https://host/#x','https://host:bad/v1'],
                 'AI_JSON_MODE':['maybe'],'AI_TEMPERATURE':['nan','-1','3'],
                 'AI_THINKING':['auto'],'AI_TOKEN_PARAMETER':['arbitrary'],'AI_TIMEOUT_SECONDS':['0','601']}
        for name,values in invalid.items():
            for value in values:
                with self.subTest(name=name,value=value),patch.dict(os.environ,{**env,name:value},clear=True):
                    with self.assertRaises(ValueError):runtime_config.settings()

    def test_redirect_never_forwards_authorization(self):
        import urllib.request, urllib.error
        from ai_transport import NoRedirect
        req=urllib.request.Request('https://first.invalid/v1/chat/completions',data=b'{}',headers={'Authorization':'Bearer private-test-key'})
        for code in (301,302,303,307,308):
            with self.subTest(code=code),self.assertRaises(urllib.error.HTTPError):
                NoRedirect().redirect_request(req,None,code,'redirect',{},'https://second.invalid')

    def test_generic_json_mode_and_temperature(self):
        env={'AI_BASE_URL':'https://compatible.invalid/v1','AI_MODEL':'chat','AI_API_KEY':'private-test-key',
             'AI_JSON_MODE':'true','AI_TEMPERATURE':'0.5','AI_THINKING':'omit'}
        raw={'choices':[{'finish_reason':'stop','message':{'content':'{"ok":true}'}}]}
        with patch.dict(os.environ,env,clear=True),patch('ai_transport.send_request',return_value=io.BytesIO(json.dumps(raw).encode())) as call:
            Reviewer(self.base/'generic-json-api').ask('check','Return JSON',{},30)
            req=call.call_args.args[0];body=json.loads(req.data)
            self.assertEqual(req.get_header('Authorization'),'Bearer private-test-key')
            self.assertEqual(body['response_format'],{'type':'json_object'})
            self.assertEqual(body['temperature'],0.5)
            self.assertNotIn('thinking',body)

    def test_invalid_and_truncated_responses_are_rejected_and_preserved(self):
        env={'AI_BASE_URL':'https://compatible.invalid/v1','AI_MODEL':'chat','AI_API_KEY':'private-test-key'}
        for label,content,finish in [('invalid','not JSON','stop'),('array','[]','stop'),('truncated','{"ok":true}','length')]:
            raw={'choices':[{'finish_reason':finish,'message':{'content':content}}]}
            out=self.base/('response-'+label)
            with self.subTest(label=label),patch.dict(os.environ,env,clear=True),patch('ai_transport.send_request',return_value=io.BytesIO(json.dumps(raw).encode())):
                with self.assertRaises(ValueError):Reviewer(out).ask('check','Return JSON',{},30)
                self.assertEqual(len(list(out.glob('*/response.json'))),1)
                self.assertEqual(len(list(out.glob('*/answer.json'))),0)

    def test_release_package_excludes_credentials_outputs_and_data(self):
        import importlib.util, zipfile
        project=Path(__file__).resolve().parents[1]
        spec=importlib.util.spec_from_file_location('package_release_test',project/'scripts/package_release.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        root=self.base/'package';root.mkdir()
        for name in module.ROOT_FILES:(root/name).write_text('public configuration template',encoding='utf-8')
        for name in module.DIRECTORIES:(root/name).mkdir()
        (root/'src/main.py').write_text('pass\n',encoding='utf-8')
        (root/'.env').write_text('DEEPSEEK_API_KEY=private-test-key',encoding='utf-8')
        (root/'outputs').mkdir();(root/'outputs/report.md').write_text('private report',encoding='utf-8')
        (root/'data').mkdir();(root/'data/log.json').write_text('{}',encoding='utf-8')
        destination=self.base/'release.zip';module.package(destination,root)
        with zipfile.ZipFile(destination) as z:
            self.assertIn('.env.example',z.namelist())
            self.assertNotIn('.env',z.namelist());self.assertNotIn('outputs/report.md',z.namelist())
            self.assertNotIn('data/log.json',z.namelist())
        with self.assertRaises(ValueError):module.package(destination,root)

    def test_online_branches_and_public_output_with_mock_api(self):
        root=self.base/'online_input';root.mkdir()
        events=[{'record_id':str(i),'source':'p','source_type':'process','target':'f','target_type':'file',
                 'operation':'read','timestamp':f'2026-01-01T00:00:0{i}Z','label':'malicious','step_id':'s'+str(i),
                 'instance_id':'attack','host':'host'} for i in (1,2)]
        (root/'events.jsonl').write_bytes(b'\n'.join(orjson.dumps(e) for e in events)+b'\n')
        save(root/'ground_truth.json',{'scenario_name':'attack','storyline_steps':[{'storyline_id':'s1','description':'read file'}, {'storyline_id':'s2','description':'read file'}]})
        tasks=[]
        def respond(request,timeout):
            body=json.loads(request.data);payload=json.loads(body['messages'][1]['content']);instruction=body['messages'][0]['content']
            if 'profiles' in payload:
                tasks.append('mapping');answer={'profiles':[{'id':p['id'],'role':p['detected_role'],'decision':'retain','evidence_ids':[]} for p in payload['profiles']]}
            elif 'annotation_tasks' in payload:
                from test_annotation_semantics import verdict
                tasks.append('annotation');answer={'items':[verdict(t) for t in payload['annotation_tasks']]}
                answer['items'][0]['step_checks'][0]['state']='contradicted'
                answer['items'][0]['step_checks'][0]['reason']='Test: wrong step assignment'
            elif 'candidate_identity_links' in payload:
                tasks.append('chain');answer={'chains':[{'scenario':'attack','state':'insufficient','stages':[],'edges':[],'reason':'No different tactical objectives evidenced'}]}
            else:
                tasks.append('gt');answer={'items':[]}
                for step in payload['steps']:
                    evidence=step['evidence']
                    answer['items'].append({'step_id':step['step_id'],'state':'partial' if evidence else 'insufficient',
                       'citations':[{'record_id':evidence[0]['record_id'],'field':'observed.operation','value':evidence[0]['observed']['operation']}] if evidence else [],
                       'missing_claims':['Limited behavioral evidence'],'reason':'Fixture response'})
            response={'model':body['model'],'choices':[{'finish_reason':'stop','message':{'content':json.dumps(answer)}}],
                      'usage':{'prompt_tokens':10,'completion_tokens':10,'total_tokens':20}}
            return io.BytesIO(json.dumps(response).encode())
        out=self.base/'online_output'
        with patch.dict(os.environ,{'AI_BASE_URL':'https://compatible.invalid/v1','AI_MODEL':'test-chat','AI_API_KEY':'private-test-key'},clear=True),patch('ai_transport.send_request',side_effect=respond):
            execute(root,out)
        score=read(out/'quality_score.json')
        self.assertTrue(score['input_complete']);self.assertEqual(set(score['metrics']),set(METRICS))
        self.assertIsInstance(score['total_score'],float)
        self.assertTrue({'mapping','gt','annotation','chain'}<=set(tasks))
        self.assertEqual(score['metrics']['R01']['score'],50)
        self.assertEqual(score['metrics']['R01']['coverage']['selected_records'],2)
        self.assertEqual(score['protocol'],'fixed-evidence-v2-all-semantic')
        self.assertEqual(score['metrics']['A03']['score'],0)
        self.assertTrue(all(isinstance(m['score'],(int,float)) for m in score['metrics'].values()))
        for artifact in read(out/'artifact_manifest.json')['artifacts']:
            self.assertEqual(sha(out/artifact['path']),artifact['sha256'])

    def test_resuming_offline_does_not_reuse_semantic_points(self):
        root=self.base/'resume_input';root.mkdir();out=self.base/'resume_output'
        save(root/'event.json',{'record_id':'one','source':'p','source_type':'process','target':'f','target_type':'file','operation':'read','timestamp':'2026-01-01T00:00:00Z','label':'benign'})
        execute(root,out,offline=True)
        existing=read(out/'quality_score.json');existing['metrics']['R01']['score']=100
        save(out/'quality_score.json',existing)
        with patch.dict(os.environ,{},clear=True),patch('ai_transport.send_request',side_effect=AssertionError('offline egress')):
            execute(root,out,offline=True,resume=True)
        result=read(out/'quality_score.json')
        self.assertEqual(result['metrics']['R01']['score'],0)
        self.assertEqual(result['metrics']['R01']['status'],'not_run_offline')
