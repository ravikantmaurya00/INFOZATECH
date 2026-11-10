const SCEN=[["Online attack, throttled login",1e2],["Offline, slow hash (bcrypt)",1e5],["Offline, fast hash (MD5 on GPUs)",1e11]];
const $=id=>document.getElementById(id);
const L2=Math.log2;

function fmtTime(s){
  if(s<1)return"Instantly";
  const U=[["second",1,60],["minute",60,60],["hour",3600,24],["day",86400,365],["year",31557600,1e3]];
  const y=s/31557600;
  if(y>1.38e10)return"Longer than the universe has existed";
  if(y>=1e12)return Math.round(y/1e12)+" trillion years";
  if(y>=1e9)return Math.round(y/1e9)+" billion years";
  if(y>=1e6)return Math.round(y/1e6)+" million years";
  if(y>=1e3)return Math.round(y/1e3)+" thousand years";
  for(let k=U.length-1;k>=0;k--){if(s>=U[k][1]){const v=Math.round(s/U[k][1]);return v+" "+U[k][0]+(v===1?"":"s")}}
  return"Instantly";
}
const RATING=[["Very weak","var(--red)",1],["Weak","var(--red)",2],["Fair","var(--amber)",3],["Strong","var(--teal)",4],["Excellent","var(--teal)",5]];
function rate(b){return b<28?0:b<40?1:b<60?2:b<80?3:4}

function render(a){
  const pw=$("pw").value;
  const segs=document.querySelectorAll("#meter i");
  $("sBits").textContent=Math.round(a.bits);$("sPool").textContent=a.pool;$("sLen").textContent=a.n;
  // chips
  const chips=$("chips");chips.textContent="";
  for(const s of a.segs){const e=document.createElement("span");e.className="chip "+(s.type==="rand"?"":s.type);
    e.textContent=$("eye").getAttribute("aria-pressed")==="true"?s.t:"•".repeat(s.t.length);chips.appendChild(e)}
  // verdict
  if(!a.n){$("label").textContent="Waiting for input";$("sub").textContent="Start typing to see a rating";
    segs.forEach(s=>s.style.background="");}
  else{const r=RATING[rate(a.bits)];$("label").textContent=r[0];$("label").style.color=r[1];
    $("sub").textContent=a.flags.common?"This is one of the most common passwords":"About "+Math.round(a.bits)+" bits after pattern penalties";
    segs.forEach((s,i)=>s.style.background=i<r[2]?r[1]:"");}
  // cracks
  const box=$("cracks");box.textContent="";
  for(const[name,rate_]of SCEN){
    const secs=a.n?Math.pow(2,Math.max(a.bits-1,0))/rate_:0;
    const pct=a.n?Math.min(100,Math.max(2,(Math.log10(Math.max(secs,1))/19.5)*100)):0;
    const col=secs<86400*30?"var(--red)":secs<31557600*100?"var(--amber)":"var(--teal)";
    const d=document.createElement("div");d.className="crack";
    d.innerHTML='<div class="row"><span></span><span></span></div><div class="big"></div><div class="bar"><div></div></div>';
    d.querySelector(".row span").textContent=name;
    d.querySelectorAll(".row span")[1].textContent=rate_.toExponential(0).replace("e+","×10^")+" guesses/s";
    d.querySelector(".big").textContent=a.n?fmtTime(secs):"—";
    const bar=d.querySelector(".bar div");bar.style.width=pct+"%";bar.style.background=col;
    box.appendChild(d);
  }
  // checks
  const f=a.flags,C=[
    ["At least 12 characters",a.n>=12],
    ["16 or more characters (better)",a.n>=16],
    ["Upper and lower case letters",/[a-z]/.test(pw)&&/[A-Z]/.test(pw)],
    ["Includes digits",/\d/.test(pw)],
    ["Includes symbols",/[^A-Za-z0-9]/.test(pw)],
    ["Not a common password",a.n>0&&!f.common],
    ["No dictionary words or leetspeak",a.n>0&&!f.word],
    ["No sequences, repeats, or years",a.n>0&&!f.seq&&!f.rep&&!f.year]
  ];
  const ul=$("checks");ul.textContent="";
  for(const[t,ok]of C){const li=document.createElement("li");li.className=ok?"ok":"";
    const m=document.createElement("span");m.className="m";m.textContent=ok?"✓":"–";
    const s=document.createElement("span");s.textContent=t;li.append(m,s);ul.appendChild(li)}
  const tips=[];
  if(a.n){
    if(f.common)tips.push("Pick something that is not on any common list; this one is guessed almost immediately.");
    if(a.n<16)tips.push("Add length first. Each extra character multiplies the work for an attacker.");
    if(f.word)tips.push("Swapping letters for symbols (a→@) does not hide a word. Use several unrelated words or random characters.");
    if(f.seq||f.rep)tips.push("Avoid keyboard walks, runs like 123 or abc, and repeated blocks.");
    if(f.year)tips.push("Birth years and recent years are among the first things tried.");
    if(!tips.length&&a.bits<80)tips.push("Good start. Make it longer to push past 80 bits.");
  }
  const tl=$("tips");tl.textContent="";tips.forEach(t=>{const li=document.createElement("li");li.textContent=t;tl.appendChild(li)});
}

let last={n:0,pool:0,bits:0,segs:[],flags:{}},timer,seq=0;
async function check(){
  const mine=++seq,pw=$("pw").value;
  try{
    const r=await fetch("/api/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password:pw})});
    if(mine!==seq)return;last=await r.json();render(last);
  }catch(e){$("sub").textContent="Cannot reach the Python server. Is app.py running?"}
  $("breach").style.color="";
  $("breach").textContent=pw?"Press Check (or Enter) to look this password up in known data breaches.":"";
}
async function sha1(s){const b=await crypto.subtle.digest("SHA-1",new TextEncoder().encode(s));
  return[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("").toUpperCase()}
async function idle(pw,bits){
  try{
    const h=await sha1(pw),pre=h.slice(0,5),suf=h.slice(5);
    const r=await fetch("/api/breach/"+pre);
    if(!r.ok)throw 0;
    const hit=(await r.text()).split("\n").map(l=>l.trim().split(":")).find(p=>p[0]===suf&&+p[1]>0);
    $("breach").textContent=hit?"Found in "+Number(hit[1]).toLocaleString()+" known data breaches. Do not use this password anywhere.":"Not found in known data breaches.";
    $("breach").style.color=hit?"var(--red)":"var(--teal)";
  }catch(e){$("breach").textContent="Breach check unavailable (no internet).";$("breach").style.color=""}
  fetch("/api/record",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({bits})}).then(loadStats).catch(()=>{});
}
async function loadStats(){
  try{
    const s=await (await fetch("/api/stats")).json(),box=$("stats");box.textContent="";
    if(!s.total){box.textContent="No checks recorded yet. Type a password and press Check.";return}
    s.labels.forEach((l,i)=>{const d=document.createElement("div");d.className="crack";
      d.innerHTML='<div class="row"><span></span><span></span></div><div class="bar"><div></div></div>';
      const sp=d.querySelectorAll(".row span");sp[0].textContent=l;sp[1].textContent=s.counts[i];
      const bar=d.querySelector(".bar div");bar.style.width=(s.counts[i]/s.total*100)+"%";bar.style.background=RATING[i][1];box.appendChild(d)});
    const p=document.createElement("p");p.className="note";p.textContent=s.total+" checks, average "+s.avg_bits+" bits";box.appendChild(p);
  }catch(e){}
}
async function gen(){
  const q=new URLSearchParams({length:$("glen").value,upper:+$("gU").checked,digits:+$("gD").checked,symbols:+$("gS").checked});
  $("lenOut").textContent=$("glen").value;
  try{$("gen").textContent=(await (await fetch("/api/generate?"+q)).json()).password}catch(e){$("gen").textContent="Server not reachable"}
}
const EMPTY={n:0,pool:0,bits:0,segs:[],flags:{}};
$("pw").addEventListener("input",()=>{
  if($("live").checked){check();return}
  seq++;last=EMPTY;render(EMPTY);               // hide results until Check is clicked
  $("label").style.color="";$("label").textContent=$("pw").value?"Not checked yet":"Waiting for input";
  $("sub").textContent=$("pw").value?"Click Check (or press Enter) to see the strength":"Type a password, then click Check";
  $("breach").style.color="";$("breach").textContent="";
});
$("live").addEventListener("change",()=>{$("live").checked?check():$("pw").dispatchEvent(new Event("input"))});
$("eye").addEventListener("click",e=>{const on=e.target.getAttribute("aria-pressed")!=="true";
  e.target.setAttribute("aria-pressed",on);e.target.textContent=on?"Hide":"Show";$("pw").type=on?"text":"password";render(last)});
$("gBtn").addEventListener("click",gen);
["glen","gU","gD","gS"].forEach(i=>$(i).addEventListener("input",gen));
$("cpBtn").addEventListener("click",async()=>{try{await navigator.clipboard.writeText($("gen").textContent);$("cpBtn").textContent="Copied";setTimeout(()=>$("cpBtn").textContent="Copy",1400)}catch(e){$("cpBtn").textContent="Select and copy manually"}});
$("useBtn").addEventListener("click",()=>{$("pw").value=$("gen").textContent;check()});
$("theme").addEventListener("click",()=>{const r=document.documentElement;
  const dark=r.dataset.theme?r.dataset.theme==="dark":matchMedia("(prefers-color-scheme:dark)").matches;
  r.dataset.theme=dark?"light":"dark"});
gen();render(last);loadStats();

$("chk").addEventListener("click",async()=>{
  const pw=$("pw").value;
  if(!pw){$("breach").style.color="";$("breach").textContent="Type a password first.";return}
  await check();                                   // strength, breakdown, crack times
  $("breach").style.color="";$("breach").textContent="Checking breaches…";
  idle(pw,last.bits);                              // breach lookup + anonymous stats
});
$("pw").addEventListener("keydown",e=>{if(e.key==="Enter")$("chk").click()});
