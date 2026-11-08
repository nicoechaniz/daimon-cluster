"""Public disclosure selection, exact-version evidence and honest source failure."""
from copy import deepcopy
import json
import pytest
from tools import children_public_advisories as advisory


def inventory(packages=None):
    return {'schema':'children-application-inventory/v1','state':'observed',
            'environments':{'/private/DO-NOT-UPLOAD':{'packages':packages or [
                {'name':'Public_One','version':'1.2','direct_url_present':False},
                {'name':'private-project','version':'3','direct_url_present':False},
                {'name':'public-vcs','version':'4','direct_url_present':True}]}}}


def detail(identifier,aliases=None,fixed=True,withdrawn=None):
    return {'id':identifier,'aliases':aliases or [],'modified':'2026-11-08T00:00:00Z',
            'withdrawn':withdrawn,'summary':'Selected public package issue',
            'affected':[{'package':{'ecosystem':'PyPI','name':'public-one'},
                         'ranges':[{'type':'ECOSYSTEM','events':[{'introduced':'0'}]+([{'fixed':'2'}] if fixed else [])}]}]}


def test_only_explicit_public_tuples_are_sent_and_identical_receivers_deduplicate():
    calls=[]
    def transport(path,payload=None):
        calls.append((path,payload));return {'results':[{}]}
    result=advisory.match([inventory(),inventory()],['public-one','public-vcs'],transport)
    assert len(calls)==1
    encoded=json.dumps(calls)
    assert 'DO-NOT-UPLOAD' not in encoded and 'private-project' not in encoded and 'public-vcs' not in encoded
    assert result['public_queries']==[{'package':{'ecosystem':'PyPI','name':'public-one'},'version':'1.2'}]
    assert result['state']=='matched' and result['coverage']=='partial' and result['unassessed']


def test_aliases_no_fix_and_non_cve_malicious_records_are_preserved():
    records={'GHSA-one':detail('GHSA-one',['CVE-2026-10000']),
             'CVE-2026-10000':detail('CVE-2026-10000',['GHSA-one']),
             'MAL-2026-1':detail('MAL-2026-1',fixed=False)}
    def transport(path,payload=None):
        return {'results':[{'vulns':[{'id':k} for k in records]}]} if path=='querybatch' else records[path.split('/')[-1]]
    result=advisory.match([inventory()],['public-one'],transport)
    assert len(result['active_alias_groups'])==2
    mal=next(v for v in result['records'] if v['id']=='MAL-2026-1')
    assert mal['affected'][0]['fix_events_listed']==[]
    assert mal['primary_record'].endswith('/MAL-2026-1')


def test_withdrawal_and_modified_record_are_re_evaluated_with_new_version():
    record=detail('GHSA-one');calls=[]
    def transport(path,payload=None):
        calls.append((path,payload))
        return {'results':[{'vulns':[{'id':'GHSA-one'}]}]} if path=='querybatch' else record
    first=advisory.match([inventory()],['public-one'],transport)
    record['modified']='2026-11-08T01:00:00Z';record['withdrawn']='2026-11-08T01:00:00Z'
    changed=inventory([{'name':'public-one','version':'1.3','direct_url_present':False}])
    second=advisory.match([changed],['public-one'],transport)
    assert first['query_sha256']!=second['query_sha256']
    assert second['records'][0]['modified']!=first['records'][0]['modified']
    assert second['active_alias_groups']==[] and len(second['records'])==1


def test_pagination_follows_only_pending_query_and_refuses_repeated_token():
    count=0
    def transport(path,payload=None):
        nonlocal count
        count+=1
        if count==1:return {'results':[{'next_page_token':'one'}]}
        assert payload['queries'][0]['page_token']=='one'
        return {'results':[{}]}
    assert advisory.match([inventory()],['public-one'],transport)['state']=='matched'
    with pytest.raises(ValueError,match='pagination'):
        advisory.match([inventory()],['public-one'],lambda *args:{'results':[{'next_page_token':'repeat'}]})


@pytest.mark.parametrize('response',[{}, {'results':[]}, {'results':[{'error':'unavailable'}]}, {'results':[{'vulns':[{}]}]}])
def test_bad_or_partial_source_is_not_empty_success(response):
    with pytest.raises(ValueError):advisory.match([inventory()],['public-one'],lambda *args:response)


def test_unobserved_or_no_public_versions_are_not_clean():
    with pytest.raises(ValueError):advisory.match([dict(inventory(),state='unavailable')],['public-one'])
    with pytest.raises(ValueError):advisory.match([inventory()],['other-public-name'])


def test_detail_must_bind_id_and_requested_package():
    with pytest.raises(ValueError):advisory.record('GHSA-one',detail('GHSA-other'),{'public-one'})
    with pytest.raises(ValueError):advisory.record('GHSA-one',detail('GHSA-one'),{'other'})


def test_private_local_version_labels_stay_offline():
    private=inventory([{'name':'public-one','version':'1.2+private-company','direct_url_present':False}])
    queries,unselected=advisory.select([inventory(),private],['public-one'])
    assert len(queries)==1 and queries[0]['version']=='1.2' and unselected>0
    assert 'private-company' not in json.dumps(queries)


class Response:
    def __init__(self,data,url):self.data=data;self.url=url;self.offset=0
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def geturl(self):return self.url
    def read1(self,count):
        value=self.data[self.offset:self.offset+count];self.offset+=len(value);return value


class Opener:
    def __init__(self,response):self.response=response;self.requests=[]
    def open(self,request,timeout):self.requests.append(request);return self.response


def test_real_transport_shape_redirect_and_stream_capacity_guards():
    transport=advisory.Transport();opener=Opener(Response(b'{"results":[]}',advisory.API+'querybatch'));transport.opener=opener
    assert transport('querybatch',{'queries':[]})=={'results':[]}
    assert json.loads(opener.requests[0].data)=={'queries':[]}
    assert transport.calls==1 and transport.bytes==14
    transport=advisory.Transport();transport.opener=Opener(Response(b'{}','https://other.example/'))
    with pytest.raises(ValueError,match='redirect'):transport('querybatch',{'queries':[]})
    transport=advisory.Transport();transport.opener=Opener(Response(b'x'*(4*1024*1024+1),advisory.API+'querybatch'))
    with pytest.raises(ValueError,match='capacity'):transport('querybatch',{'queries':[]})
    transport=advisory.Transport();transport.calls=40
    with pytest.raises(ValueError,match='capacity'):transport('querybatch',{})
