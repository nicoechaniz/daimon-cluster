'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../../clusterctl/homes/assets/work-view.js'), 'utf8');
function mount() {
  const events = {}, frameEvents = {}, nodes = [], classes = new Set(), capabilities = [];
  const frame = {dataset:{src:'https://content.test/r/retained/index.html',downloadRoot:'/works/'+'a'.repeat(32)+'/'+'b'.repeat(64)+'/',downloadFiles:'[]'},
    contentWindow:{postMessage:v=>capabilities.push(v)}, addEventListener:(name,fn)=>frameEvents[name]=fn, before:n=>nodes.push(n)};
  const document = {querySelector:()=>frame,body:{classList:{add:x=>classes.add(x),remove:x=>classes.delete(x)}},
    createElement:tag=>({tag,children:[],setAttribute(){},append(n){this.children.push(n);},remove(){this.removed=true;}})};
  const location={hash:'',pathname:'/view/'+'a'.repeat(32),search:'?display=work'};
  vm.runInNewContext(source,{document,location,URL,window:{addEventListener:(name,fn)=>events[name]=fn},history:{replaceState(){}},JSON});
  frameEvents.load();
  return {frame,document,location,nodes,classes,capabilities,load:frameEvents.load,
    send(data,overrides={}){events.message({source:frame.contentWindow,origin:'null',data,...overrides});}};
}
const offer={type:'home-artifact:related-work',resource:'c'.repeat(32),label:'Open 3D viewer'};
test('offers one ordinary same-home link without automatic navigation or HTML',()=>{
  const app=mount();assert.equal(app.capabilities[0].relatedWork,true);
  app.send({...offer,label:'<img src=x onerror=alert(1)>'});
  assert.equal(app.nodes.length,1);const link=app.nodes[0].children[0];
  assert.equal(link.href,'/view/'+'c'.repeat(32)+'?display=work');
  assert.equal(link.textContent,'<img src=x onerror=alert(1)>');
  assert.equal(app.location.pathname,'/view/'+'a'.repeat(32));
  assert.ok(app.classes.has('has-related-work'));
  app.send({...offer,resource:'d'.repeat(32)});assert.equal(app.nodes.length,1);
  app.load();assert.equal(app.nodes[0].removed,true);assert.ok(!app.classes.has('has-related-work'));
  app.send(offer);assert.equal(app.nodes.length,2);
});
test('other frames, non-opaque origins, URLs and malformed labels cannot offer navigation',()=>{
  for(const overrides of [{source:{}},{origin:'https://content.test'}]){const app=mount();app.send(offer,overrides);assert.equal(app.nodes.length,0);}
  for(const resource of ['https://evil.test/','../access/owner','c'.repeat(33),'C'.repeat(32),null]){const app=mount();app.send({...offer,resource});assert.equal(app.nodes.length,0);}
  for(const label of ['', ' ', 'x'.repeat(81), null, 4]){const app=mount();app.send({...offer,label});assert.equal(app.nodes.length,0);}
});
