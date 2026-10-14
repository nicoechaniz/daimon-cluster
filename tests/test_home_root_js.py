"""Exercise parent route containment without a live home or browser credential."""

import json
import os
from pathlib import Path
import subprocess


def test_root_parent_messages_cannot_call_owner_routes_or_open_external_pages():
    source = (
        Path(__file__).parents[1] / "clusterctl/homes/assets/home-root.js"
    ).read_text()
    script = r"""
    const vm=require('node:vm');let listener, navigations=[],posts=[];
    const child={postMessage:data=>posts.push(data)};
    const link={},button={addEventListener(){}},panel={hidden:true,querySelector:s=>s==='a'?link:button};
    const frame={dataset:{rootRoutes:JSON.stringify({'/':'index.html','/journal/day/index.html':'journal/day/index.html'})},contentWindow:child,addEventListener(){}};
    const document={querySelector:s=>s.startsWith('iframe')?frame:panel};
    const window={addEventListener:(type,fn)=>listener=fn};
    vm.runInNewContext(SOURCE,{document,window,location:{assign:path=>navigations.push(path)},URL,JSON,Object});
    listener({source:{},origin:'null',data:{type:'home-root:route',path:'/'}});
    listener({source:child,origin:'https://untrusted.example',data:{type:'home-root:route',path:'/'}});
    listener({source:child,origin:'null',data:{type:'home-root:route',path:'/owner/one/home-root-select'}});
    if(navigations.length)throw Error('Unqualified navigation');
    listener({source:child,origin:'null',data:{type:'home-root:route',path:'/journal/day/index.html',fragment:'javascript:bad'}});
    if(navigations.length)throw Error('Invalid route fragment');
    listener({source:child,origin:'null',data:{type:'home-root:route',path:'/journal/day/index.html',fragment:'#media'}});
    listener({source:child,origin:'null',data:{type:'home-root:external',url:'javascript:alert(1)'}});
    if(!panel.hidden)throw Error('Unsafe external link');
    listener({source:child,origin:'null',data:{type:'home-root:external',url:'https://selected.example/page'}});
    if(panel.hidden || link.href!=='https://selected.example/page' || navigations.length!==1)throw Error('External pages must require a fresh link click');
    process.stdout.write(JSON.stringify({route:navigations[0],parentCapabilities:posts.length,externalClickRequired:true}));
    """
    result = subprocess.check_output(
        [
            os.environ.get("HOMEMAKER_NODE", "node"),
            "-e",
            "const SOURCE=" + json.dumps(source) + ";" + script,
        ],
        text=True,
        timeout=30,
    )
    assert json.loads(result)["route"] == "/journal/day/index.html#media"
