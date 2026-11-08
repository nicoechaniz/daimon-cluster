#!/usr/bin/env python3
"""Bounded OSV leads for explicitly selected public Python names, never a verdict."""
import hashlib
import json
import re
import time
import urllib.request
import urllib.parse

API='https://api.osv.dev/v1/'
ID=re.compile(r'[A-Za-z0-9][-A-Za-z0-9._:]{0,100}')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None


def normalize(name):
    if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}',name):
        raise ValueError('public_package_identity_required')
    return re.sub(r'[-_.]+','-',name).lower()


def select(inventories, public_names):
    if (not isinstance(public_names,list) or not 1<=len(public_names)<=64
            or len({normalize(n) for n in public_names})!=len(public_names)):
        raise ValueError('bounded_explicit_public_name_selection_required')
    allowed={normalize(n) for n in public_names};queries=set();unselected=0
    for inventory in inventories:
        if inventory.get('schema')!='children-application-inventory/v1' or inventory.get('state')!='observed':
            raise ValueError('current_observed_application_inventory_required')
        for env in inventory.get('environments',{}).values():
            for package in env.get('packages',[]):
                name=normalize(package['name']);version=package['version']
                if name not in allowed or package.get('direct_url_present') is not False:
                    unselected+=1;continue
                if not isinstance(version,str) or len(version)>128:
                    raise ValueError('bounded_declared_version_required')
                # Local/private build labels stay offline; only ordinary release syntax.
                if not re.fullmatch(r'(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?',version):
                    unselected+=1;continue
                queries.add((name,version))
                if len(queries)>64:raise ValueError('public_query_capacity')
    return [{'package':{'ecosystem':'PyPI','name':n},'version':v} for n,v in sorted(queries)],unselected


class Transport:
    def __init__(self):
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
        self.bytes=0;self.calls=0;self.deadline=time.monotonic()+120

    def __call__(self,path,payload=None):
        if self.calls>=40 or time.monotonic()>=self.deadline:raise ValueError('advisory_request_capacity')
        if path!='querybatch' and not re.fullmatch(r'vulns/[A-Za-z0-9][-A-Za-z0-9._:]{0,100}',path):
            raise ValueError('closed_advisory_route_required')
        url=API+path;raw=json.dumps(payload,separators=(',',':')).encode() if payload is not None else None
        if raw is not None and len(raw)>65536:raise ValueError('advisory_request_byte_capacity')
        request=urllib.request.Request(url,data=raw,headers={'Content-Type':'application/json','User-Agent':'children-public-advisories/1'})
        self.calls+=1;limit=4*1024*1024 if path=='querybatch' else 1024*1024
        with self.opener.open(request,timeout=min(10,max(.1,self.deadline-time.monotonic()))) as reply:
            if reply.geturl()!=url:raise ValueError('advisory_redirect_refused')
            chunks=[];seen=0
            while seen<=limit:
                if time.monotonic()>self.deadline:raise ValueError('advisory_deadline')
                chunk=reply.read1(min(65536,limit+1-seen))
                if not chunk:break
                chunks.append(chunk);seen+=len(chunk)
            data=b''.join(chunks)
        self.bytes+=len(data)
        if len(data)>limit or self.bytes>32*1024*1024:raise ValueError('advisory_response_capacity')
        if time.monotonic()>self.deadline:raise ValueError('advisory_deadline')
        return json.loads(data)


def record(identifier, value, queried_names):
    if not isinstance(value,dict) or value.get('id')!=identifier:raise ValueError('advisory_record_identity')
    aliases=value.get('aliases',[])
    if (not isinstance(aliases,list) or len(aliases)>16
            or any(not isinstance(a,str) or not ID.fullmatch(a) for a in aliases)):
        raise ValueError('advisory_alias_capacity')
    modified=value.get('modified');withdrawn=value.get('withdrawn')
    if not isinstance(modified,str) or not 1<=len(modified)<=64:raise ValueError('advisory_revision_required')
    if withdrawn is not None and (not isinstance(withdrawn,str) or len(withdrawn)>64):
        raise ValueError('advisory_withdrawal_invalid')
    affected=[];entries=value.get('affected',[])
    if not isinstance(entries,list) or len(entries)>64:raise ValueError('advisory_affected_capacity')
    for entry in entries:
        if not isinstance(entry,dict):raise ValueError('advisory_affected_shape')
        package=entry.get('package',{})
        if not isinstance(package,dict):raise ValueError('advisory_package_shape')
        if package.get('ecosystem')!='PyPI':continue
        name=normalize(package['name'])
        if name not in queried_names:continue
        ranges=entry.get('ranges',[])
        if not isinstance(ranges,list) or len(ranges)>16:raise ValueError('advisory_range_capacity')
        fixed=[]
        for scope in ranges:
            if not isinstance(scope,dict):raise ValueError('advisory_range_shape')
            events=scope.get('events',[])
            if not isinstance(events,list) or len(events)>64:raise ValueError('advisory_event_capacity')
            for event in events:
                if not isinstance(event,dict):raise ValueError('advisory_event_shape')
                if 'fixed' in event:
                    if not isinstance(event['fixed'],str) or len(event['fixed'])>128:raise ValueError('advisory_fixed_version_capacity')
                    fixed.append(event['fixed'])
        if len(set(fixed))>16:raise ValueError('advisory_fixed_event_capacity')
        affected.append({'name':name,'fix_events_listed':sorted(set(fixed))})
    if not affected:raise ValueError('advisory_package_binding_missing')
    summary=value.get('summary','')
    if not isinstance(summary,str):raise ValueError('advisory_summary_type')
    return {'id':identifier,'aliases':sorted(set(aliases)),'modified':modified,'withdrawn':withdrawn,
            'summary':summary[:256],'affected':affected,'source_sha256':hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest(),
            'primary_record':API+'vulns/'+identifier}


def group(records):
    parents={}
    def root(value):
        parents.setdefault(value,value)
        while parents[value]!=value:
            parents[value]=parents[parents[value]];value=parents[value]
        return value
    for item in records:
        names=[item['id'],*item['aliases']]
        for name in names:parents[root(name)]=root(names[0])
    groups={}
    for item in records:
        if item['withdrawn'] is not None:continue
        key=root(item['id']);groups.setdefault(key,[]).append(item['id'])
    return sorted(sorted(ids) for ids in groups.values())


def match(inventories, public_names, transport=None):
    queries,unselected=select(inventories,public_names);transport=transport or Transport()
    report={'schema':'children-public-advisories/v1','checked':int(time.time()),'coverage':'partial',
            'query_sha256':hashlib.sha256(json.dumps(queries,sort_keys=True).encode()).hexdigest(),
            'public_queries':queries,'unselected_declarations':unselected,'records':[],'matches':[],
            'unassessed':['artifact-authenticity','loaded-package-and-exposure-applicability',
                          'unselected-private-and-non-Python-software','sources-outside-OSV'],
            'source':'OSV public version query; candidate evidence only'}
    if not queries:raise ValueError('no_observed_eligible_public_versions')
    pending=[(i,q) for i,q in enumerate(queries)];ids={};matches={i:set() for i in range(len(queries))};seen=set()
    for page in range(4):
        if not pending:break
        response=transport('querybatch',{'queries':[q for _,q in pending]})
        results=response.get('results') if isinstance(response,dict) else None
        if not isinstance(results,list) or len(results)!=len(pending):raise ValueError('advisory_batch_shape')
        next_page=[]
        for (i,q),result in zip(pending,results):
            if not isinstance(result,dict) or set(result)-{'vulns','next_page_token'}:
                raise ValueError('advisory_result_shape')
            vulns=result.get('vulns',[])
            if not isinstance(vulns,list) or len(vulns)>256:raise ValueError('advisory_candidate_capacity')
            for item in vulns:
                if not isinstance(item,dict):raise ValueError('advisory_id_shape')
                identifier=item.get('id')
                if not isinstance(identifier,str) or not ID.fullmatch(identifier):raise ValueError('advisory_id_required')
                ids.setdefault(identifier,set()).add(queries[i]['package']['name']);matches[i].add(identifier)
                if len(ids)>32:raise ValueError('advisory_record_capacity')
            token=result.get('next_page_token')
            if token:
                if not isinstance(token,str) or len(token)>4096 or (i,token) in seen:raise ValueError('advisory_pagination_invalid')
                seen.add((i,token));next_page.append((i,{**queries[i],'page_token':token}))
        pending=next_page
    if pending:raise ValueError('advisory_pagination_capacity')
    for identifier,names in sorted(ids.items()):
        report['records'].append(record(identifier,transport('vulns/'+identifier),names))
    report['matches']=[{'query':q,'ids':sorted(matches[i])} for i,q in enumerate(queries)]
    report['active_alias_groups']=group(report['records']);report['state']='matched'
    report['needs_triage']=bool(report['active_alias_groups'])
    if isinstance(transport,Transport):
        report['network_requests']=transport.calls;report['response_bytes']=transport.bytes
    if len(json.dumps(report).encode())>128*1024:raise ValueError('advisory_receipt_capacity')
    return report
