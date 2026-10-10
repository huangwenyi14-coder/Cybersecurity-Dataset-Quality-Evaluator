"""Normalized seven-field events -> time/behavior evidence and calibrated Gaussian scores.

No network calls. Never infer a universal ideal event rate or manufacture missing fields.
"""
from core import *
from event_contract import validate as validate_event, present
from decimal import Decimal, InvalidOperation, ROUND_FLOOR
import argparse, math, sqlite3, statistics

VERSION = 'authenticity-v1.0.0'
SECOND = 1000000000
WINDOWS = (1, 10, 60)
FEATURE_FAMILIES = {'rate': ('log_mean_eps', 'log_p95_eps'),
                    'burst': ('log_burst_ratio',), 'continuity': ('zero_second_fraction',)}


def checked_path(value):
    p = Path(value).resolve()
    return p


def timestamp_ns(t):
    """Deterministic conversion; naive local and relative clocks remain separately grouped."""
    if not isinstance(t, dict) or t.get('basis') not in ('utc', 'relative', 'local_unspecified'):
        return None
    try:
        if t.get('unit') == 'iso8601':
            if t['basis'] == 'relative':
                return None
            d = datetime.datetime.fromisoformat(str(t['value']).replace('Z', '+00:00'))
            if t['basis'] == 'utc' and d.tzinfo is None:
                return None
            if t['basis'] == 'local_unspecified' and d.tzinfo is not None:
                return None
            epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) if d.tzinfo else datetime.datetime(1970, 1, 1)
            delta = d - epoch
            n = (delta.days * 86400 + delta.seconds) * SECOND + delta.microseconds * 1000
        else:
            factors = {'s': SECOND, 'ms': 1000000, 'us': 1000, 'ns': 1}
            v = Decimal(str(t['value'])) * factors[t['unit']]
            if not v.is_finite():
                return None
            n = int(v.to_integral_value(rounding=ROUND_FLOOR))
        return n if -(2**63) < n < 2**63 else None
    except (ValueError, TypeError, KeyError, InvalidOperation, OverflowError):
        return None


def gaussian(value, center, tolerance, scale):
    if not all(math.isfinite(x) for x in (value, center, tolerance, scale)) or tolerance < 0 or scale <= 0:
        raise ValueError('Gaussian parameters must be finite, tolerance >= 0 and scale > 0')
    distance = max(0., abs(value - center) - tolerance)
    return 100. * math.exp(-0.5 * (distance / scale)**2)


def quantile(hist, q):
    """Exact nearest-rank quantile over compressed frequencies, including implicit zeros."""
    n = sum(hist.values())
    if not n:
        return None
    rank = max(1, math.ceil(q * n)); seen = 0
    for value, count in sorted(hist.items()):
        seen += count
        if seen >= rank:
            return value


def describe(hist):
    hist = {k: v for k, v in hist.items() if v > 0}; n = sum(hist.values())
    if not n:
        return {'n': 0, 'mean': None, 'p50': None, 'p95': None, 'max': None}
    return {'n': n, 'mean': sum(k*v for k, v in hist.items()) / n,
            'p50': quantile(hist, .5), 'p95': quantile(hist, .95), 'max': max(hist)}


def group_for(event, config):
    loc = event['provenance']; fmt = event.get('native_format') or 'unspecified'
    family = (event.get('native_type') or 'unspecified').split(':')[0]
    if fmt == 'cdm':family = 'cdm'  # An event type is not a separate collection sensor.
    sensor = fmt + '/' + family
    host = event.get('host') if present(event.get('host')) else '@source:' + loc['file']
    # Zeek HTTP `host` is a destination website, not the collection host.
    # Compare collector streams, not remote services accidentally named "host".
    if fmt in ('zeek', 'flow', 'packet'):
        source = Path(loc['file'])
        host = config.get('collector_by_file', {}).get(loc['file'], '@capture-file:' + loc['file'])
        if fmt == 'zeek':
            stream = config.get('sensor_stream_by_file', {}).get(loc['file'], source.name.split('.')[0])
            sensor += '/' + stream
    basis = (event.get('event_time') or {}).get('basis', 'unavailable')
    clock = config.get('clock_domains', {}).get(loc['file'])
    if not clock:
        clock = 'host_clock' if basis == 'utc' else 'file_clock:' + loc['file']
    context = config.get('comparison_context_by_sensor', {}).get(sensor, config.get('comparison_context'))
    group = {'sensor': sensor, 'host': host, 'basis': basis, 'clock_domain': clock,
             'comparison_context': context}
    gid = hashlib.sha256(orjson.dumps(group, option=orjson.OPT_SORT_KEYS)).hexdigest()[:20]
    return gid, group


def reference_key(group):
    if not group.get('comparison_context') or group['basis'] == 'unavailable':
        return None
    return json.dumps([group['sensor'], group['basis'], group['comparison_context'], group.get('interval',{}).get('scope','no_time_interval')], ensure_ascii=False)


def analyze(normalized, output, config=None, reference=None, annotation_review=None):
    normalized = checked_path(normalized); output = checked_path(output); config = config or {}
    if reference is None and config.get('reference_policy') != 'none' and (RES/'darpa_tc_authenticity_reference.json').exists():
        reference = RES/'darpa_tc_authenticity_reference.json'
    if output == normalized or output.is_relative_to(normalized) or normalized.is_relative_to(output):
        raise ValueError('Analysis output must be separate from the normalized input')
    if output.exists():
        raise ValueError('Use a new authenticity output directory; existing evidence is not overwritten')
    summary = read(normalized/'summary.json')
    filenames = ['summary.json', '03_events.valid.jsonl.gz', '03_events.incomplete.jsonl.gz']
    hashes = {name: sha(normalized/name) for name in filenames}
    if annotation_review is not None and annotation_review.get('normalized_sha256') != hashes:
        raise ValueError('Annotation semantic review belongs to different normalized input')
    dataset_hashes = sorted({x['sha256'] for x in summary.get('files', []) if x.get('sha256')})
    fingerprint = hashlib.sha256(orjson.dumps(dataset_hashes or hashes)).hexdigest()
    output.mkdir(parents=True)
    save(output/'config.json', config)
    db = sqlite3.connect(str(output/'observations.sqlite'))
    db.execute('CREATE TABLE events(id TEXT PRIMARY KEY,gid TEXT,ns INTEGER,sec INTEGER,behavior TEXT,locator TEXT)')
    db.execute('CREATE TABLE gaps(gid TEXT,left_ns INTEGER,right_ns INTEGER,left_id TEXT,right_id TEXT,left_locator TEXT,right_locator TEXT)')
    groups = {}; counters = Counter(); labels = Counter(); label_sources = Counter(); ref_examples = {}
    try:
        for filename, expected_valid in [('03_events.valid.jsonl.gz', True), ('03_events.incomplete.jsonl.gz', False)]:
            for e in lines(normalized/filename):
                counters['input_records'] += 1
                valid = not validate_event(e)
                if valid != expected_valid:
                    raise ValueError('Normalized validity partition disagrees with seven-field contract: ' + str(e.get('event_id')))
                gid, spec = group_for(e, config)
                ns = timestamp_ns(e.get('event_time')); sec = ns // SECOND if ns is not None else None
                behavior = '|'.join(e[k] for k in ('subject_type','operation','object_type')) if valid else None
                loc = json.dumps(e['provenance'], ensure_ascii=False, sort_keys=True)
                row = (e['event_id'], gid, ns, sec, behavior, loc)
                try:
                    db.execute('INSERT INTO events VALUES (?,?,?,?,?,?)', row)
                except sqlite3.IntegrityError:
                    old = db.execute('SELECT * FROM events WHERE id=?', (e['event_id'],)).fetchone()
                    if old != row:
                        raise ValueError('Conflicting normalized physical event identity')
                    counters['repeated_physical_ids'] += 1
                    continue
                g = groups.setdefault(gid, {**spec, 'id': gid, 'records': 0, 'valid_records': 0, 'timed_records': 0,
                                           'behavior_counts': Counter(), 'files': set()})
                g['records'] += 1; g['valid_records'] += int(valid); g['timed_records'] += int(ns is not None)
                g['files'].add(e['provenance']['file'])
                if behavior:
                    g['behavior_counts'][behavior] += 1
                counters['unique_physical_records'] += 1; counters['valid_records'] += int(valid)
                counters['timed_records'] += int(ns is not None)
                labels[e.get('label','unknown')] += 1
                label=e.get('label')
                if label in ('benign','malicious','contaminated','conflict'):
                    counters['assigned_label_records']+=1
                    if label!='conflict' and any(r.get('label')==label and r.get('file') and isinstance(r.get('row'),int) and r['row']>0 for r in e.get('label_evidence',[])):
                        counters['event_level_traceable_labels']+=1
                for r in e.get('label_evidence', []):
                    label_sources[r['file']] += 1; ref_examples.setdefault(r['file'], r)
                if counters['unique_physical_records'] % 10000 == 0:
                    db.commit()
        if counters['input_records'] != summary['counts']['records']:
            raise ValueError('Normalized record count differs from summary')
        db.execute('CREATE INDEX event_time ON events(gid,ns)'); db.commit()
        profiles = []; behavior_profiles = []; gap_count = 0
        with gzip.open(output/'time_windows.jsonl.gz', 'wb') as windows, gzip.open(output/'gap_candidates.jsonl.gz', 'wb') as gaps:
            for gid, g in sorted(groups.items()):
                g['files'] = sorted(g['files']); behavior_total = sum(g['behavior_counts'].values())
                g['behavior_proportions'] = {k:v/behavior_total for k,v in sorted(g['behavior_counts'].items())} if behavior_total else {}
                bounds = db.execute('SELECT MIN(sec),MAX(sec) FROM events WHERE gid=? AND sec IS NOT NULL', (gid,)).fetchone()
                g['time_features'] = {}; g['windows'] = {}; interval_hist = Counter(); previous = None
                if bounds[0] is not None:
                    start, end = bounds[0], bounds[1]+1
                    capture = config.get('capture_intervals', {}).get(gid)
                    if capture:
                        if not capture.get('evidence') or not isinstance(capture.get('start_second'), int) or not isinstance(capture.get('end_second'), int):
                            raise ValueError('Capture bounds need integer seconds and an evidence citation')
                        if capture['start_second'] > start or capture['end_second'] < end:
                            raise ValueError('Declared capture interval excludes observed events')
                        start, end = capture['start_second'], capture['end_second']
                    g['interval'] = {'start_second':start, 'end_second_exclusive':end,
                                     'basis':g['basis'], 'scope':'declared_capture' if capture else 'first_to_last_observation_only',
                                     'evidence':capture.get('evidence') if capture else None,
                                     'boundary_censoring':not bool(capture)}
                    for ns, eid, locator in db.execute('SELECT ns,id,locator FROM events WHERE gid=? AND ns IS NOT NULL ORDER BY ns,id',(gid,)):
                        if previous:
                            delta = ns - previous[0]
                            interval_hist[delta/SECOND] += 1
                            if delta > 0:
                                db.execute('INSERT INTO gaps VALUES (?,?,?,?,?,?,?)',(gid,previous[0],ns,previous[1],eid,previous[2],locator))
                        previous = (ns,eid,locator)
                    g['inter_event_seconds'] = describe(interval_hist)
                    positive = {k:v for k,v in interval_hist.items() if k>0}
                    typical = quantile(positive,.5) or 0
                    gap_threshold = max(float(config.get('gap_min_seconds',60)), float(config.get('gap_factor',10))*typical)
                    if not math.isfinite(gap_threshold) or gap_threshold <= 0:
                        raise ValueError('Gap candidate thresholds must be positive and finite')
                    g['gap_detection'] = {'threshold_seconds':gap_threshold,'classification':'candidate_only_not_proven_capture_loss','candidates':0}
                    for left,right,lid,rid,lloc,rloc in db.execute('SELECT left_ns,right_ns,left_id,right_id,left_locator,right_locator FROM gaps WHERE gid=? AND (right_ns-left_ns)>? ORDER BY left_ns',(gid,gap_threshold*SECOND)):
                        emit(gaps,{'group':gid,'start_second':left/SECOND,'end_second':right/SECOND,'duration_seconds':(right-left)/SECOND,
                                   'left_event':lid,'right_event':rid,'left_provenance':json.loads(lloc),'right_provenance':json.loads(rloc),
                                   'status':'suspected_gap','capture_scope':g['interval']['scope'],'not_a_confirmed_interruption':True})
                        gap_count+=1;g['gap_detection']['candidates']+=1
                    for width in WINDOWS:
                        # Negative clocks use mathematical floor, not SQLite truncation toward zero.
                        bucket_sql = 'CAST(sec / ? AS INTEGER) - CASE WHEN sec < 0 AND sec % ? != 0 THEN 1 ELSE 0 END'
                        query = 'SELECT '+bucket_sql+' AS bucket,COUNT(*) FROM events WHERE gid=? AND sec IS NOT NULL GROUP BY bucket ORDER BY bucket'
                        hist = Counter(); rate_hist = Counter(); first_bucket=start//width; last_bucket=(end-1)//width; cursor=first_bucket
                        occupied=0
                        for bucket,count in db.execute(query,(width,width,gid)):
                            if bucket>cursor:
                                emit(windows,{'group':gid,'window_seconds':width,'first_bucket':cursor,'last_bucket':bucket-1,'repeat':bucket-cursor,'count':0,'scope':g['interval']['scope']})
                                hist[0]+=bucket-cursor;rate_hist[0.]+=bucket-cursor
                            exposure=min(end,(bucket+1)*width)-max(start,bucket*width)
                            emit(windows,{'group':gid,'window_seconds':width,'first_bucket':bucket,'last_bucket':bucket,'repeat':1,'count':count,'exposure_seconds':exposure,'events_per_second':count/exposure,'scope':g['interval']['scope']})
                            hist[count]+=1;rate_hist[count/exposure]+=1;cursor=bucket+1;occupied+=1
                        if cursor<=last_bucket:
                            emit(windows,{'group':gid,'window_seconds':width,'first_bucket':cursor,'last_bucket':last_bucket,'repeat':last_bucket-cursor+1,'count':0,'scope':g['interval']['scope']})
                            hist[0]+=last_bucket-cursor+1;rate_hist[0.]+=last_bucket-cursor+1
                        g['windows'][str(width)]={'count_distribution':describe(hist),'rate_distribution':describe(rate_hist),'occupied_windows':occupied,
                                                 'zero_window_fraction':hist[0]/sum(hist.values()),'duration_weighted_mean_eps':g['timed_records']/(end-start)}
                    one=g['windows']['1'];stats=one['rate_distribution']
                    g['time_features']={'log_mean_eps':math.log1p(one['duration_weighted_mean_eps']), 'log_p95_eps':math.log1p(stats['p95']),
                                        'log_burst_ratio':math.log1p(stats['p95']/(stats['p50']+1)), 'zero_second_fraction':one['zero_window_fraction']}
                # Behavior proportions use valid events only; undefined empty windows are not zero-valued behaviors.
                hist_by_behavior=defaultdict(Counter); active_behavior_windows=0; current=None; window_counts=Counter()
                def flush_behavior():
                    nonlocal active_behavior_windows
                    if not window_counts:return
                    active_behavior_windows+=1;total=sum(window_counts.values())
                    for key,n in window_counts.items():hist_by_behavior[key][n/total]+=1
                for sec,bhv in db.execute('SELECT sec,behavior FROM events WHERE gid=? AND sec IS NOT NULL AND behavior IS NOT NULL ORDER BY sec',(gid,)):
                    bucket=sec//60
                    if current is not None and bucket!=current:flush_behavior();window_counts.clear()
                    current=bucket;window_counts[bhv]+=1
                flush_behavior()
                details=[]
                for bhv,n in sorted(g['behavior_counts'].items()):
                    h=hist_by_behavior[bhv];h[0.]+=active_behavior_windows-sum(h.values())
                    details.append({'behavior':bhv,'count':n,'proportion':n/behavior_total,'window_60s_proportion':describe(h)})
                behavior_profiles.append({'group':gid,'sensor':g['sensor'],'host':g['host'],'denominator_valid_events':behavior_total,
                                          'excluded_incomplete_events':g['records']-g['valid_records'],'active_60s_windows':active_behavior_windows,'behaviors':details})
                profiles.append(g)
        db.commit()
        manifest={'protocol':VERSION,'normalized':str(normalized),'input_sha256':hashes,'dataset_fingerprint':fingerprint,'source_file_sha256':dataset_hashes,
                  'input_complete':bool(summary['complete_input_scan']),'config':config,'counters':counters,'groups':profiles,'gap_candidates':gap_count,
                  'feature_policy':'per sensor/host/clock; observed-span silence is descriptive, not proven capture loss; behavior only from seven-field-valid events',
                  'time':stamp(),'python':os.sys.executable}
        save(output/'features.json',manifest);save(output/'behavior_distribution.json',behavior_profiles)
        inventory=read(normalized/'01_inventory.json') if (normalized/'01_inventory.json').exists() else {'files':[]}
        annotation={'label_counts':labels,'join_evidence_sources':[{'file':p,'references':n,'example':ref_examples[p]} for p,n in label_sources.items()],
                    'input_label_formats':[{'file':s['path'],'schema':s.get('schema'),'role':s['role']} for s in inventory['files'] if s['role'] in ('label','ground_truth')],
                    'granularity':'normalized event assignments; source labels may have a different granularity',
                    'declared_annotation_method':config.get('annotation_method'), 'declaration_status':'user_configuration' if config.get('annotation_method') else 'not_established',
                    'observed_mapping':'source references retained' if label_sources else 'embedded_labels_or_unavailable',
                    'quality_score':None,'reason':'No independent label correctness assessment; mapping evidence does not prove malicious semantics'}
        modes={'physical_labels':'GT physical-anchor association','story_gt':'scenario/step GT','aggregate_labels':'aggregate label sets'}
        annotation['observed_annotation_artifacts']=sorted({modes[s.get('schema')] for s in annotation['input_label_formats'] if s.get('schema') in modes})
        annotation['assigned_label_records']=counters['assigned_label_records']
        annotation['event_level_traceable_labels']=counters['event_level_traceable_labels']
        if annotation_review is not None:annotation['semantic_review']=annotation_review
        save(output/'annotation_profile.json',annotation)
        scores=score_profiles(manifest,read(checked_path(reference)) if reference else None,annotation)
        if scores.get('annotation_detail'):
            annotation['quality_score']=scores['annotation_score'];annotation['reason']=scores['annotation_detail']['reason'];save(output/'annotation_profile.json',annotation)
        save(output/'authenticity_scores.json',scores)
        if reference:save(output/'reference_profile.json',read(checked_path(reference)))
        render(output,manifest,annotation,scores)
        save(output/'verification.json',{'records_match_normalization':counters['input_records']==summary['counts']['records'],
             'valid_records_match_normalization':counters['valid_records']==summary['counts'].get('valid_records',0),
             'time_records_not_more_than_input':counters['timed_records']<=counters['unique_physical_records'],
             'source_inputs_unchanged':all(sha(normalized/n)==h for n,h in hashes.items()),'external_calls':0,'time':stamp()})
        return manifest,scores
    finally:
        db.close()


def fitted(values):
    if len(values)<3:return {'status':'insufficient_reference_groups','samples':len(values)}
    center=statistics.median(values);mad=statistics.median(abs(x-center) for x in values)
    if mad<=0:return {'status':'zero_reference_scale','samples':len(values),'center':center}
    hist=Counter(values);tol=max(center-quantile(hist,.1),quantile(hist,.9)-center)
    return {'status':'calibrated','samples':len(values),'center':center,'tolerance':tol,'scale':2*1.4826*mad,
            'scale_policy':'2 * 1.4826 * MAD; no hidden epsilon floor'}


def calibrate(paths, output, declaration):
    output=checked_path(output)
    if output.exists():raise ValueError('Reference output already exists')
    if declaration.get('kind') not in ('real_capture','test_fixture') or not declaration.get('evidence'):
        raise ValueError('Explicit real-capture evidence declaration is required; tests must declare test_fixture')
    bins=defaultdict(list);seen=set();fingerprints=set();source_hashes=set();inputs=[]
    for path in paths:
        path=checked_path(path);p=read(path)
        if p.get('protocol')!=VERSION or not p['input_complete']:raise ValueError('Reference requires complete, compatible normalized analysis')
        for g in p['groups']:
            key=reference_key(g)
            if key is None:raise ValueError('Reference comparison_context must be explicitly supplied')
            identity=(p['dataset_fingerprint'],g['id'])
            if identity in seen:raise ValueError('Duplicate reference group cannot inflate calibration sample count')
            seen.add(identity)
            if g['valid_records']!=g['records'] or g['timed_records']!=g['records']:
                raise ValueError('Reference groups must have complete time and behavior fields; do not calibrate on an adapter subset')
            bins[key].append(g)
        fingerprints.add(p['dataset_fingerprint']);source_hashes.update(p['source_file_sha256']);inputs.append({'file':str(path),'sha256':sha(path)})
    models={}
    for key,groups in bins.items():
        time_models={f:fitted([g['time_features'][f] for g in groups if f in g['time_features']]) for names in FEATURE_FAMILIES.values() for f in names}
        keys=set().union(*(g['behavior_proportions'] for g in groups))
        distributions={k:fitted([g['behavior_proportions'].get(k,0) for g in groups]) for k in sorted(keys)}
        reference_mean={k:sum(g['behavior_proportions'].get(k,0) for g in groups)/len(groups) for k in sorted(keys)}
        models[key]={'reference_groups':len(groups),'time':time_models,'behavior':distributions,'behavior_mean':reference_mean}
    result={'protocol':VERSION,'declaration':declaration,'inputs':inputs,'dataset_fingerprints':sorted(fingerprints),
            'source_file_sha256':sorted(source_hashes),'models':models,'fit_policy':'group macro observations; q10-q90 tolerance, broad Gaussian; >=3 groups is a computability guard, not statistical validation',
            'time':stamp()}
    save(output,result);return result


def score_profiles(profile,reference,annotation=None):
    if reference and reference.get('protocol')=='darpa-tc-authenticity-v1.0.0':
        from authenticity_tc import score
        return score(profile,reference,annotation)
    from authenticity_tc import annotation_score
    ann=annotation_score(annotation or {})
    base={'protocol':VERSION,'annotation_score':ann['score'],'annotation_detail':ann,'annotation_protocol':'annotation-semantics-v1','authenticity_total':None,
          'total_reason':'R01 uses semantic review; unavailable statistical reference components remain unavailable',
          'time_score':None,'behavior_score':None,'groups':[],'input_complete':profile['input_complete']}
    if reference is None:base['status']='reference_unavailable';return base
    if reference.get('protocol')!=VERSION:raise ValueError('Incompatible reference protocol')
    if profile['dataset_fingerprint'] in reference['dataset_fingerprints'] or set(profile['source_file_sha256']) & set(reference['source_file_sha256']):
        raise ValueError('Self-comparison or overlapping source files cannot establish authenticity')
    base['reference_kind']=reference['declaration']['kind']
    for g in profile['groups']:
        key=reference_key(g);model=reference['models'].get(key);row={'group':g['id'],'comparison_key':key,'time_score':None,'behavior_score':None,'time_features':{},'behavior_features':{}}
        if model is None:row['status']='no_comparable_reference';base['groups'].append(row);continue
        for name,value in g['time_features'].items():
            params=model['time'].get(name,{})
            value_score=gaussian(value,params['center'],params['tolerance'],params['scale']) if params.get('status')=='calibrated' else None
            row['time_features'][name]={'value':value,'reference':params,'score':value_score}
        families=[]
        for names in FEATURE_FAMILIES.values():
            vals=[row['time_features'].get(n,{}).get('score') for n in names]
            families.append(sum(vals)/len(vals) if all(v is not None for v in vals) else None)
        if all(v is not None for v in families) and g['timed_records']==g['records'] and g['records']:
            row['time_score']=sum(families)/len(families)
        p=g['behavior_proportions'];q=model['behavior_mean'];known_weight=0;contribution=0
        for bhv in sorted(set(p)|set(q)):
            weight=(p.get(bhv,0)+q.get(bhv,0))/2;params=model['behavior'].get(bhv,{})
            value_score=gaussian(p.get(bhv,0),params['center'],params['tolerance'],params['scale']) if params.get('status')=='calibrated' else None
            row['behavior_features'][bhv]={'proportion':p.get(bhv,0),'reference_mean':q.get(bhv,0),'reference':params,'weight':weight,'score':value_score}
            if value_score is not None:known_weight+=weight;contribution+=weight*value_score
        row['behavior_known_weight']=known_weight;row['behavior_confirmed_contribution']=contribution
        if abs(known_weight-1)<1e-9 and g['valid_records']==g['records'] and g['records']:
            row['behavior_score']=contribution
        row['status']='scored' if row['time_score'] is not None and row['behavior_score'] is not None else 'partial_calibration_or_fields'
        base['groups'].append(row)
    if profile['input_complete'] and base['groups']:
        for metric in ('time_score','behavior_score'):
            vals=[g[metric] for g in base['groups']]
            if all(v is not None for v in vals):base[metric]=sum(vals)/len(vals)
    base['status']='scored_components' if base['time_score'] is not None and base['behavior_score'] is not None else 'needs_calibration_or_complete_input'
    if reference['declaration']['kind']=='test_fixture':base['status']='test_fixture_only_not_dataset_authenticity'
    return base


def render(output,profile,annotation,scores):
    from reports import table,link
    def num(v):return '待标定/不可确定' if v is None else f'{v:.4f}'
    tc=scores.get('protocol')=='darpa-tc-authenticity-v1.0.0'
    from metric_catalog import VERSION as system_version
    text='# 真实性：标注语义、时间特征、行为分布 '+system_version+'\n\n'
    text+='输入为已规范化记录；R01读取模型语义核验及本地引用检查结果，时间和行为分布由本地统计。单独运行本模块不调用模型，未核验时R01为0。构建方式、实体活动和行为顺序均不参与。\n\n'
    text+=table(['一级','二级','三级','结果'],[['真实性','标注质量','R01 标注语义支持',num(scores['annotation_score'] or 0.)],['真实性','数据真实度','R02 时间特征',num(scores['time_score'] if scores['time_score'] is not None else 0.)],['真实性','数据真实度','R03 行为分布',num(scores['behavior_score'] if scores['behavior_score'] is not None else 0.)]])
    if tc:
        text+=f"\n**真实性总分：{num(sum(w*(scores[k] or 0.) for k,w in [('annotation_score',.2),('time_score',.4),('behavior_score',.4)])) if profile['input_complete'] else '未完成全量扫描'}/100**。参考为用户指定的 DARPA TC E3 THEIA，权重：标注20%、时间40%、行为40%。按相关字段可用的规范化记录计算，覆盖率另外披露；跨采集器分布差异会影响结果，不是真实来源概率。\n\n"
        text+=scores['annotation_detail']['reason']+'\n\n'
        if scores.get('preview_scores'):text+='仅预览条件分数：`'+json.dumps(scores['preview_scores'])+'`，不发布全量分数。\n\n'
        if scores.get('self_reference'):text+='本数据与参考来源重叠，属于自参考描述，不能作为独立真实性验证。\n\n'
    else:text+='\n未提供可用的DARPA或其他真实参考，保留统计及待标定状态。测试参考产生的数字只验证函数。\n\n'
    detail=scores.get('annotation_detail',{})
    text+=f"\nR01分层抽查：步骤 {detail.get('total_steps',0)} 个，抽中记录 {detail.get('selected_records',0)} 条，已核验记录 {detail.get('reviewed_records',0)} 条。评分单位：{detail.get('unit','无')}；确认 {detail.get('supported',0)} / {detail.get('denominator',0)}。\n\n"
    text+=table(['记录统计','数量'],list(profile['counters'].items()))
    text+=f"\n输入全量完成：{profile['input_complete']}；分组 {len(profile['groups'])}；疑似断档 {profile['gap_candidates']}。\n\n"
    text+='时间分析保留有身份和可解释时间的待补全记录；行为分析仅用七字段完整记录。UTC 同主机同传感器可合并分片，相对时间默认按源文件隔离。观察起止之间的零事件窗口只表示未观测到事件，不证明采集中断。\n\n'
    rows=[]
    for g in profile['groups']:
        w=g['windows'].get('1',{});s=w.get('rate_distribution',{})
        rows.append([g['id'],g['sensor'],g['host'],g['basis'],g['records'],g['timed_records'],g['valid_records'],num(w.get('duration_weighted_mean_eps')),num(s.get('p50')),num(s.get('p95')),num(w.get('zero_window_fraction')),g.get('gap_detection',{}).get('candidates',0)])
    text+=table(['分组','日志类型','主机/来源','时间基准','记录','有时间','字段完整','平均事件/秒','P50','P95','零秒占比','疑似断档'],rows)
    totals=Counter()
    for g in profile['groups']:totals.update(g['behavior_counts'])
    denominator=sum(totals.values())
    text+='\n下表是字段完整记录的总体行为构成，只用于描述；参考评分仍分传感器和环境比较。未知映射不当成行为不存在。\n\n'
    text+=table(['主体—操作—客体','记录数','占字段完整记录比例'],[[k.replace('|',' → '),n,f'{100*n/denominator:.4f}%'] for k,n in totals.most_common()])
    text+='\n评分函数：`100*exp(-0.5*(max(0,abs(x-center)-tolerance)/scale)^2)`。速率在 log(1+x) 空间比较；范围内满分，超出后平缓下降。未要求原始分布正态，也未把均匀行为或高频日志当成真实标准。\n\n'
    text+='标注连接来源：\n\n'+table(['文件','引用次数'],[[r['file'],r['references']] for r in annotation['join_evidence_sources']])
    text+='\n可观察标注材料：'+('；'.join(annotation.get('observed_annotation_artifacts',[])) or '未识别')+'。这是材料/连接方式，不能据此认定由人工还是模型产生。\n\n'
    text+='\n'+ '\n'.join(link(output/f,title) for f,title in [('annotation_profile.json','标注方式证据'),('features.json','全部时间统计与输入身份'),('time_windows.jsonl.gz','1/10/60 秒窗口（零窗口压缩表示）'),('gap_candidates.jsonl.gz','疑似断档及前后原始定位'),('behavior_distribution.json','逐行为分布与60秒窗口特征'),('authenticity_scores.json','高斯参数、代入值和分项分'),('verification.json','检查结果')])+'\n'
    (output/'report.md').write_text(text,encoding='utf-8')


def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    a=sub.add_parser('analyze');a.add_argument('--normalized',required=True,type=Path);a.add_argument('--output',required=True,type=Path);a.add_argument('--config',type=Path);a.add_argument('--reference',type=Path)
    c=sub.add_parser('calibrate');c.add_argument('--profiles',required=True,nargs='+',type=Path);c.add_argument('--output',required=True,type=Path);c.add_argument('--declaration',required=True,type=Path)
    args=p.parse_args()
    if args.command=='analyze':
        profile,scores=analyze(args.normalized,args.output,read(checked_path(args.config)) if args.config else None,args.reference)
        print(json.dumps({'records':profile['counters'],'groups':len(profile['groups']),'gap_candidates':profile['gap_candidates'],'status':scores['status'],'report':str(args.output/'report.md')},ensure_ascii=True))
    else:
        result=calibrate(args.profiles,args.output,read(checked_path(args.declaration)));print(json.dumps({'reference_groups':{k:v['reference_groups'] for k,v in result['models'].items()}},ensure_ascii=True))


if __name__=='__main__':main()
