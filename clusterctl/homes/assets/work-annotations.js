// Human-initiated viewport notes. The opaque child never receives a login cookie.
(()=>{
'use strict';
const frame=document.querySelector('iframe[data-src]');if(!frame)return;
let pending=null,serial=0,snapshot=null,operation=null,photo=null,submitted=null,strokes=[],drawing=false,points=0;
const button=document.createElement('button');button.type='button';button.hidden=true;
button.textContent='✎ Mark view';button.setAttribute('aria-label','Freeze and annotate this viewport');button.className='review-mark-button';
const dialog=document.createElement('dialog');dialog.className='review-note-dialog';
dialog.innerHTML='<form method="dialog"><header><strong>Mark this view</strong><button value="cancel" aria-label="Close annotation">×</button></header></form><p>The view stays frozen while you draw.</p><canvas aria-label="Draw on the frozen model with a finger, pen or mouse"></canvas><div class="review-note-tools"><label>Color <input type="color" value="#ff4f57"></label><label>Width <input type="range" min="2" max="16" value="5"></label><button type="button" data-undo>Undo</button><button type="button" data-save>Done · save and copy image</button><button type="button" data-copy hidden>Copy image</button></div><p role="status" aria-live="polite"></p><a data-link hidden target="_blank" rel="noopener">Open saved view</a><input data-url readonly hidden aria-label="Saved view link"><button type="button" data-copy-link hidden>Copy link</button>';
const sheet=document.createElement('link');sheet.rel='stylesheet';sheet.href='/work-annotations.css';document.head.append(sheet);
document.body.append(button,dialog);
const canvas=dialog.querySelector('canvas'),ctx=canvas.getContext('2d'),status=dialog.querySelector('[role=status]'),save=dialog.querySelector('[data-save]');
function rpc(method,source=null){return new Promise((resolve,reject)=>{
 if(pending){reject(Error('Viewer is busy'));return;}
 const id='note-'+(++serial),timer=setTimeout(()=>{pending=null;reject(Error('Viewer did not confirm capture'));},5000);
 pending={id,resolve,reject,timer};frame.contentWindow.postMessage({schema:'dm.review-adapter/request-v1',id,method,source,argument:null},'*');
});}
window.addEventListener('message',event=>{
 if(event.source!==frame.contentWindow||event.origin!=='null')return;
 const data=event.data;
 if(data?.type==='dm.review-adapter:ready'){button.hidden=data.capabilities?.imageCapture!==true;return;}
 if(data?.schema!=='dm.review-adapter/response-v1'||data.id!==pending?.id)return;
 const request=pending;pending=null;clearTimeout(request.timer);data.ok?request.resolve(data.result):request.reject(Error('Capture could not be confirmed'));
});
function repaint(){ctx.clearRect(0,0,canvas.width,canvas.height);if(photo)ctx.drawImage(photo,0,0);ctx.lineCap='round';ctx.lineJoin='round';
 for(const stroke of strokes){ctx.strokeStyle=stroke.color;ctx.lineWidth=stroke.width;ctx.beginPath();for(let i=0;i<stroke.points.length;i++){const [x,y]=stroke.points[i];i?ctx.lineTo(x,y):ctx.moveTo(x,y);}ctx.stroke();}}
function point(event){const r=canvas.getBoundingClientRect();return [Math.max(0,Math.min(canvas.width,(event.clientX-r.left)*canvas.width/r.width)),Math.max(0,Math.min(canvas.height,(event.clientY-r.top)*canvas.height/r.height))];}
button.onclick=async()=>{
 button.disabled=true;status.textContent='Freezing view…';
 try{
  const capabilities=await rpc('describeCapabilities');const source=capabilities.source;
  if(!source)throw Error('The model is still loading; retry when it is visible');
  const result=await rpc('captureImage',{resource:source.resource,publicationVersion:source.publicationVersion});
  if(!result?.snapshot||typeof result.image!=='string'||!result.image.startsWith('data:image/png;base64,')||result.image.length>4194368)throw Error('Invalid viewport capture');
  const image=new Image();image.src=result.image;await image.decode();
  if(!image.width||!image.height||image.width*image.height>2000000)throw Error('Viewport exceeds image limit');
  snapshot=result.snapshot;submitted=null;operation=crypto.randomUUID().replaceAll('-','');photo=image;strokes=[];points=0;drawing=false;
  canvas.width=image.width;canvas.height=image.height;repaint();save.disabled=false;save.hidden=false;
  for(const node of dialog.querySelectorAll('[data-link],[data-url],[data-copy],[data-copy-link]'))node.hidden=true;
  status.textContent='Draw on the image. Undo removes your last stroke.';dialog.showModal();
 }catch(error){save.disabled=true;status.textContent=error.message;dialog.showModal();}finally{button.disabled=false;}
};
canvas.addEventListener('pointerdown',event=>{
 if(!photo||submitted||save.hidden||strokes.length>=256||points>=20000)return;
 event.preventDefault();canvas.setPointerCapture(event.pointerId);drawing=event.pointerId;
 strokes.push({color:dialog.querySelector('[type=color]').value,width:Number(dialog.querySelector('[type=range]').value)*canvas.width/canvas.getBoundingClientRect().width,points:[point(event)]});points++;repaint();
});
canvas.addEventListener('pointermove',event=>{if(drawing!==event.pointerId||points>=20000)return;strokes.at(-1).points.push(point(event));points++;repaint();});
for(const name of ['pointerup','pointercancel','lostpointercapture'])canvas.addEventListener(name,()=>{drawing=false;});
dialog.querySelector('[data-undo]').onclick=()=>{if(submitted)return;const stroke=strokes.pop();points-=stroke?.points.length||0;repaint();};
const blob=()=>new Promise((resolve,reject)=>canvas.toBlob(value=>value?resolve(value):reject(Error('Image export failed')),'image/png'));
async function copyImage(){if(!navigator.clipboard?.write||!window.ClipboardItem)throw Error('Image clipboard unavailable');await navigator.clipboard.write([new ClipboardItem({'image/png':blob()})]);}
dialog.querySelector('[data-copy]').onclick=()=>copyImage().then(()=>status.textContent='Image copied.').catch(()=>status.textContent='Clipboard unavailable here. Open the saved image to share it.');
dialog.querySelector('[data-copy-link]').onclick=()=>navigator.clipboard?.writeText(dialog.querySelector('[data-url]').value).then(()=>status.textContent='Link copied.').catch(()=>status.textContent='Select and copy the link below.');
save.onclick=async()=>{
 if(!photo||!snapshot)return;save.disabled=true;drawing=false;
 // Start clipboard in the click gesture; save independently if the browser refuses it.
 const copied=copyImage().then(()=>true,()=>false);status.textContent='Saving annotated view…';
 try{
  const image=canvas.toDataURL('image/png');if(image.length>4194368)throw Error('Image is too large; use a smaller viewport');
  const response=await fetch('/review-notes',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:(submitted ||= JSON.stringify({operation,snapshot,image})),signal:AbortSignal.timeout(15000)});
  const result=await response.json();if(!response.ok)throw Error(result.error==='review_note_storage_full'?'Image storage is full. Delete an older note before saving.':'Could not save. Your drawing is still here; sign in or retry the same save.');
  const url=new URL(result.url,location.origin);if(url.origin!==location.origin||!/^\/review-notes\/[a-f0-9]{32}$/.test(url.pathname))throw Error('Invalid saved view link');
  const link=dialog.querySelector('[data-link]');link.href=url.href;link.hidden=false;
  const input=dialog.querySelector('[data-url]');input.value=url.href;input.hidden=false;
  dialog.querySelector('[data-copy-link]').hidden=false;dialog.querySelector('[data-copy]').hidden=false;save.hidden=true;
  status.textContent=(await copied?'Saved · image copied.':'Saved · clipboard was unavailable. Use Copy image or open the saved view.')+' The link keeps this model’s access permissions.';
 }catch(error){status.textContent=error.message;}finally{save.disabled=false;}
};
dialog.addEventListener('close',()=>{photo=null;snapshot=null;submitted=null;strokes=[];points=0;drawing=false;canvas.width=canvas.height=1;});
window.addEventListener('pagehide',()=>{if(pending){clearTimeout(pending.timer);pending.reject(Error('View closed'));pending=null;}photo=null;strokes=[];canvas.width=canvas.height=1;});
})();
