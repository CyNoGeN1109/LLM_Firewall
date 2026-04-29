/* cynoshield app.js */
const $=s=>document.querySelector(s);
const messagesEl=$('#messages'),form=$('#chatForm'),input=$('#promptInput'),sendBtn=$('#sendButton'),stopBtn=$('#stopButton'),tmpl=$('#messageTemplate');
const fwToggle=$('#firewallToggle'),fwDot=$('#fwDot'),settingsBtn=$('#settingsToggle'),sysRow=$('#sysRow'),sysPrompt=$('#systemPrompt');
const flowLog=$('#flowLog'),runtimeDot=$('#runtimeStatus'),runtimeLbl=$('#runtimeLabel'),pipeVerdict=$('#pipeVerdict');
const pnIn=$('#pn-in'),pnFw=$('#pn-fw'),pnLlm=$('#pn-llm'),pnOut=$('#pn-out'),pa1=$('#pa-1'),pa2=$('#pa-2'),pa3=$('#pa-3');
let conversation=[],ctrl=null,chatModel='qwen3:1.7b',fwModel='qwen3:1.7b';
const TIMEOUT=90000;
const TYPE_LABEL={send:'SEND',inspect:'SCAN',allow:'ALLOW',block:'BLOCK',stream:'STREAM',done:'DONE',info:'INFO'};
const WELCOME=`cynoshield is running.\n\ntoggle the firewall OFF to send prompts straight to the model.\nturn it ON and try injections like "ignore all instructions" — watch the pipeline stop it.`;

init();
async function init(){addMsg('ai',WELCOME);bind();log('info','initializing…');await loadConfig();await checkHealth();}

function bind(){
  form.addEventListener('submit',e=>{e.preventDefault();const t=input.value.trim();if(!t||ctrl)return;input.value='';autosize();send(t);});
  input.addEventListener('input',autosize);
  input.addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();form.requestSubmit();}});
  stopBtn.addEventListener('click',()=>{if(ctrl){ctrl.abort();ctrl=null;setGen(false);log('info','stopped');}});
  settingsBtn.addEventListener('click',()=>sysRow.classList.toggle('hidden'));
  fwToggle.addEventListener('change',()=>{const on=fwToggle.checked;fwDot.className='fw-dot'+(on?' on':'');log(on?'allow':'block',on?'firewall enabled':'firewall disabled — direct passthrough');});
  $('#newChat').addEventListener('click',()=>{conversation=[];messagesEl.innerHTML='';addMsg('ai',WELCOME);resetPipe();log('info','new session');input.focus();});
  $('#exportChat').addEventListener('click',()=>{const txt=conversation.map(m=>`${m.role}: ${m.content}`).join('\n\n---\n\n');const a=Object.assign(document.createElement('a'),{href:URL.createObjectURL(new Blob([txt||'(empty)'],{type:'text/plain'})),download:'cynoshield.txt'});a.click();URL.revokeObjectURL(a.href);log('info','exported');});
  const cl=$('#clearLog');if(cl)cl.addEventListener('click',()=>{flowLog.innerHTML='';log('info','log cleared');});
}

function log(type,msg){
  const t=new Date().toTimeString().slice(3,8);
  const el=document.createElement('div');el.className=`log-entry l-${type}`;
  const lbl=TYPE_LABEL[type]||type.toUpperCase();
  el.innerHTML=`<span class="log-t">${t}</span><span class="log-type">${esc(lbl)}</span><span class="log-m">${esc(msg)}</span>`;
  flowLog.appendChild(el);flowLog.scrollTop=flowLog.scrollHeight;
}

function resetPipe(){[pnIn,pnFw,pnLlm,pnOut].forEach(n=>n.className='pnode');[pa1,pa2,pa3].forEach(a=>a.className='parr');pipeVerdict.className='pverdict hidden';pipeVerdict.textContent='';}
function activateNode(n,a){[pnIn,pnFw,pnLlm,pnOut].forEach(x=>x.classList.remove('active'));n.classList.add('active');if(a)a.classList.add('active');}
function doneNode(n){n.classList.remove('active');n.classList.add('done');}
function blockNode(n,a){n.classList.remove('active');n.classList.add('blocked');if(a){a.classList.remove('active');a.classList.add('blocked');}}
function showVerdict(ok,risk){pipeVerdict.textContent=ok?`✓ allowed (${risk})`:`✗ blocked (${risk})`;pipeVerdict.className=`pverdict ${ok?'allow':'block'}`;}

async function send(text){
  resetPipe();activateNode(pnIn,null);log('send',`→ "${truncate(text,55)}"`);
  addMsg('user',text);conversation.push({role:'user',content:text});
  const ast=addMsg('ai','',true);ctrl=new AbortController();let timedOut=false;
  const tid=setTimeout(()=>{if(ctrl){timedOut=true;ctrl.abort();}},TIMEOUT);setGen(true);
  setTimeout(()=>{doneNode(pnIn);if(fwToggle.checked){activateNode(pnFw,pa1);log('inspect','inspecting prompt…');}else{doneNode(pnFw);activateNode(pnLlm,pa2);log('stream',`sending to ${chatModel}…`);}},80);
  try{
    const res=await fetch('/api/chat',{method:'POST',headers:{'Content-Type':'application/json'},signal:ctrl.signal,body:JSON.stringify({model:chatModel,firewall:fwToggle.checked,messages:conversation,system_prompt:sysPrompt.value,temperature:0.7})});
    if(!res.ok||!res.body)throw new Error('http '+res.status);
    const reader=res.body.getReader(),dec=new TextDecoder();let buf='',full='',blocked=false,first=true;
    while(true){const{value,done}=await reader.read();if(done)break;buf+=dec.decode(value,{stream:true});const parts=buf.split('\n\n');buf=parts.pop()??'';
      for(const part of parts){const ev=parseSSE(part);
        if(ev.type==='firewall'){const ok=Boolean(ev.data.allowed);showVerdict(ok,ev.data.risk);if(ok){doneNode(pnFw);activateNode(pnLlm,pa2);log('allow',`allowed — risk: ${ev.data.risk}`);log('stream',`→ ${chatModel}`);}else{log('block',`blocked — ${ev.data.attack_type}: ${ev.data.reason}`);}}
        if(ev.type==='blocked'){blocked=true;blockNode(pnFw,pa2);ast.node.classList.add('is-blocked');ast.node.classList.remove('typing');const n=document.createElement('span');n.className='block-notice';n.textContent='↳ blocked: '+(ev.data.message||'injection detected');ast.node.appendChild(n);ast.text.textContent='—';scroll();}
        if(ev.type==='token'){if(first){first=false;log('stream','streaming…');}full+=ev.data.text;ast.text.textContent=full;scroll();}
        if(ev.type==='done'&&!blocked){doneNode(pnLlm);activateNode(pnOut,pa3);setTimeout(()=>doneNode(pnOut),800);log('done',`done — ${wordCount(full)} words`);}
        if(ev.type==='error')throw new Error(ev.data.message);
      }
    }
    ast.node.classList.remove('typing');
    if(blocked){conversation.pop();}else if(full.trim()){conversation.push({role:'assistant',content:full});}else{ast.text.textContent='(no response)';}
  }catch(err){
    if(err.name==='AbortError'){ast.text.textContent=timedOut?'(timeout)':'(stopped)';if(timedOut){conversation.pop();log('block','timed out');}else log('info','stopped by user');}
    else{ast.text.textContent='(error: '+err.message+')';log('block','error: '+err.message);}
    ast.node.classList.remove('typing');resetPipe();
  }finally{clearTimeout(tid);ctrl=null;setGen(false);input.focus();}
}

function addMsg(role,text,typing=false){
  const frag=tmpl.content.cloneNode(true),node=frag.querySelector('.msg'),who=frag.querySelector('.msg-who'),pre=frag.querySelector('.msg-text');
  node.classList.add(role==='user'?'is-user':'is-ai');if(typing)node.classList.add('typing');
  who.textContent=role;pre.textContent=text;messagesEl.appendChild(frag);scroll();
  const last=messagesEl.lastElementChild;return{node:last,text:last.querySelector('.msg-text')};
}
function parseSSE(raw){const type=raw.match(/^event:\s*(.+)$/m)?.[1]??'message';const data=raw.match(/^data:\s*(.+)$/m)?.[1]??'{}';try{return{type,data:JSON.parse(data)};}catch{return{type,data:{}};}}
function autosize(){input.style.height='auto';input.style.height=Math.min(input.scrollHeight,120)+'px';}
function setGen(g){sendBtn.classList.toggle('hidden',g);stopBtn.classList.toggle('hidden',!g);input.disabled=g;}
function scroll(){messagesEl.scrollTop=messagesEl.scrollHeight;}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function truncate(s,n){return s.length>n?s.slice(0,n)+'…':s;}
function wordCount(s){return s.trim().split(/\s+/).filter(Boolean).length;}

async function loadConfig(){try{const c=await fetch('/api/config').then(r=>r.json());chatModel=c.default_model||c.model||chatModel;fwModel=c.firewall_model||fwModel;log('info',`config: model=${chatModel} fw=${fwModel}`);}catch{log('info','no /api/config endpoint');}}
async function checkHealth(){
  log('info','checking ollama…');
  try{const h=await fetch('/api/health').then(r=>r.json());
    if(h.ok&&h.firewall_available){runtimeDot.className='rdot online';runtimeLbl.textContent='online';log('allow','ollama online');}
    else if(h.ok){runtimeDot.className='rdot error';runtimeLbl.textContent='fw missing';log('block',`${fwModel} not loaded`);}
    else{runtimeDot.className='rdot error';runtimeLbl.textContent='offline';log('block','ollama not reachable');}
  }catch{runtimeDot.className='rdot error';runtimeLbl.textContent='error';log('block','connection failed — is ollama running?');}
}
