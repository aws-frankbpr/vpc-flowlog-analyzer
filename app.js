// === CONSTANTS ===
const PORTS={21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',135:'RPC',137:'NetBIOS',143:'IMAP',443:'HTTPS',445:'SMB',993:'IMAPS',1433:'MSSQL',1521:'Oracle',3306:'MySQL',3389:'RDP',5432:'PostgreSQL',5900:'VNC',6379:'Redis',8080:'HTTP-Alt',8443:'HTTPS-Alt',27017:'MongoDB'};
const PROTOS={1:'ICMP',6:'TCP',17:'UDP',47:'GRE',50:'ESP'};

const V2_FIELDS=['version','account-id','interface-id','srcaddr','dstaddr','srcport','dstport','protocol','packets','bytes','start','end','action','log-status'];
const RFC1918=[{s:0x0A000000,m:0xFF000000},{s:0xAC100000,m:0xFFF00000},{s:0xC0A80000,m:0xFFFF0000}];

let allRecords=[], geoCache={}, currentFilter={action:'all',protocol:'all',search:'',eni:'all'};

// === HELPERS ===
function isPrivate(ip){
  const p=ip.split('.').map(Number);
  const n=(p[0]<<24|p[1]<<16|p[2]<<8|p[3])>>>0;
  return RFC1918.some(r=>(n&r.m)===r.s)||ip==='0.0.0.0'||ip.startsWith('127.');
}
function formatBytes(b){
  if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';
  if(b<1073741824)return(b/1048576).toFixed(1)+' MB';return(b/1073741824).toFixed(2)+' GB';
}
function portLabel(p){return PORTS[p]?p+'/'+PORTS[p]:String(p);}
function flagStr(f){
  f=parseInt(f)||0;if(!f)return'—';
  const r=[];if(f&1)r.push('FIN');if(f&2)r.push('SYN');if(f&4)r.push('RST');if(f&16)r.push('ACK');if(f===18)return'SYN-ACK';
  return r.join('+')||'0x'+f.toString(16).padStart(2,'0');
}

// === DROP ZONE ===
const dz=document.getElementById('dropzone'),fi=document.getElementById('fileInput');
dz.onclick=()=>fi.click();
fi.onchange=e=>{if(e.target.files[0])processFile(e.target.files[0])};
dz.ondragover=e=>{e.preventDefault();dz.classList.add('over')};
dz.ondragleave=()=>dz.classList.remove('over');
dz.ondrop=e=>{e.preventDefault();dz.classList.remove('over');if(e.dataTransfer.files[0])processFile(e.dataTransfer.files[0])};

function processFile(file){
  document.getElementById('loading').classList.add('show');
  document.getElementById('loading').innerHTML='⏳ Reading file...';
  document.getElementById('results').style.display='none';
  const reader=new FileReader();
  reader.onload=e=>{
    document.getElementById('loading').innerHTML='⏳ Parsing flow log records...';
    setTimeout(()=>parseAndRender(e.target.result),100);
  };
  reader.readAsText(file);
}

function detectFields(line){
  const isCSV=line.startsWith('"');
  const parts=isCSV?line.replace(/"/g,'').split(','):line.split(/\s+/);
  const norm=parts.map(f=>f.replace(/_/g,'-'));
  if(norm.includes('version')||norm.includes('srcaddr'))return{fields:norm,isCSV};
  if(parts.length===14)return{fields:V2_FIELDS,isCSV:false};
  return null;
}

function parseAndRender(text){
  const lines=text.trim().split('\n').filter(l=>l.trim());
  if(lines.length<2){showError('File has fewer than 2 lines');return}
  const det=detectFields(lines[0]);
  if(!det){showError('Could not detect flow log format');return}
  const{fields,isCSV}=det;
  const hasHeader=isCSV||fields!==V2_FIELDS||lines[0].includes('version');
  const dataLines=hasHeader?lines.slice(1):lines;
  allRecords=[];
  for(const line of dataLines){
    const parts=isCSV?line.replace(/"/g,'').split(','):line.trim().split(/\s+/);
    if(parts.length<fields.length)continue;
    const r={};
    fields.forEach((f,i)=>r[f]=parts[i]);
    if(r['log-status']==='NODATA'||r['log-status']==='SKIPDATA')continue;
    r._srcport=parseInt(r.srcport)||0;
    r._dstport=parseInt(r.dstport)||0;
    r._protocol=parseInt(r.protocol)||0;
    r._packets=parseInt(r.packets)||0;
    r._bytes=parseInt(r.bytes)||0;
    r._start=parseInt(r.start)||0;
    r._end=parseInt(r.end)||0;
    r._tcpflags=parseInt(r['tcp-flags'])||0;
    r._private=isPrivate(r.srcaddr);
    allRecords.push(r);
  }
  if(!allRecords.length){showError('No valid flow records found');return}
  document.getElementById('loading').innerHTML='⏳ Rendering dashboard...';
  setTimeout(()=>render(),50);
}

function showError(msg){
  document.getElementById('loading').classList.remove('show');
  document.getElementById('results').style.display='block';
  document.getElementById('results').innerHTML=`<div class="card" style="border-left-color:#d13212"><b>Error:</b> ${msg}</div>`;
}

// === GEOIP ===
async function resolveOneIP(ip){
  if(geoCache[ip])return;
  try{
    const r=await fetch('https://freeipapi.com/api/json/'+ip);
    const d=await r.json();
    if(d.countryCode)geoCache[ip]={country:d.countryName||'Unknown',cc:d.countryCode||'??',org:d.regionName||'Unknown'};
  }catch(e){}
}
// Called from inline button
async function resolveIP(ip,btnId){
  const btn=document.getElementById(btnId);
  if(btn)btn.textContent='⏳';
  if(!geoCache[ip]){
    try{
      const r=await fetch('https://freeipapi.com/api/json/'+ip);
      const d=await r.json();
      if(d.countryCode)geoCache[ip]={country:d.countryName||'Unknown',cc:d.countryCode||'??',org:d.regionName||'Unknown'};
    }catch(e){if(btn)btn.textContent='❌';}
  }
  render();
}
// Resolve all public IPs — uses ip-api.com batch (100/req) via corsproxy
async function resolveAllGeo(){
  const pubIPs=[...new Set(allRecords.flatMap(r=>[r.srcaddr,r.dstaddr]).filter(ip=>!isPrivate(ip)&&!geoCache[ip]))];
  if(!pubIPs.length){alert('All IPs already resolved!');return}
  const btn=document.getElementById('resolveAllBtn');
  if(btn){btn.disabled=true;btn.textContent='⏳ 0/'+pubIPs.length+'...';}
  window._skipGeo=false;
  const batches=[];
  for(let i=0;i<pubIPs.length;i+=100)batches.push(pubIPs.slice(i,i+100));
  let done=0;
  for(const batch of batches){
    if(window._skipGeo)break;
    try{
      const r=await fetch('https://corsproxy.io/?url='+encodeURIComponent('http://ip-api.com/batch?fields=status,query,country,countryCode,org,isp'),{
        method:'POST',body:JSON.stringify(batch)
      });
      const data=await r.json();
      data.forEach(d=>{if(d.status==='success')geoCache[d.query]={country:d.country,cc:d.countryCode,org:d.org||d.isp||'Unknown'};});
    }catch(e){
      // Fallback: individual via freeipapi
      await Promise.all(batch.slice(0,20).map(ip=>resolveOneIP(ip)));
    }
    done+=batch.length;
    if(btn)btn.textContent=`⏳ ${done}/${pubIPs.length}...`;
    await new Promise(r=>setTimeout(r,1500)); // rate limit
  }
  if(btn){btn.disabled=false;btn.textContent='🌍 Resolve All GeoIP';}
  render();
}
function skipGeo(){window._skipGeo=true;render();}

function geoFor(ip){
  if(isPrivate(ip))return{country:'Private',cc:'🏠',org:'RFC1918'};
  return geoCache[ip]||null;
}
function flag(cc){
  if(cc==='🏠')return'🏠';if(!cc||cc==='??')return'🌐';
  return String.fromCodePoint(...[...cc.toUpperCase()].map(c=>0x1F1E6+c.charCodeAt(0)-65));
}
let _btnId=0;
function ipGeoCell(ip){
  const g=geoFor(ip);
  if(g)return`${flag(g.cc)} ${g.country}`;
  const id='gb'+(_btnId++);
  return`<button id="${id}" onclick="resolveIP('${ip}','${id}')" style="padding:1px 6px;font-size:.7em;border:1px solid #aab7b8;border-radius:4px;background:#fff;cursor:pointer" title="Lookup GeoIP">🔍</button>`;
}
function ipOrgCell(ip){
  const g=geoFor(ip);
  return g?g.org:'—';
}

// === THREAT SCORING (aligned with GuardDuty finding types & AWS Config restricted-common-ports) ===
// References:
//   https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html
//   https://docs.aws.amazon.com/config/latest/developerguide/restricted-common-ports.html
const HIGH_RISK_PORTS={20:'FTP-Data',21:'FTP',22:'SSH',23:'Telnet',135:'RPC',137:'NetBIOS',445:'SMB',1433:'MSSQL',3306:'MySQL',3389:'RDP',4333:'Reserved',5432:'PostgreSQL',5900:'VNC',6379:'Redis',27017:'MongoDB'};

function buildThreatData(recs){
  const map={};
  recs.forEach(r=>{
    const ip=r.srcaddr;
    if(!map[ip])map[ip]={ports:new Set(),portCounts:{},rejected:0,total:0,hrPorts:new Set(),synOnly:0};
    const d=map[ip];
    d.ports.add(r._dstport);
    d.portCounts[r._dstport]=(d.portCounts[r._dstport]||0)+1;
    d.total++;
    if(r.action==='REJECT')d.rejected++;
    if(HIGH_RISK_PORTS[r._dstport])d.hrPorts.add(r._dstport);
    if(r._tcpflags===2)d.synOnly++;
  });
  return map;
}

function scoreSrc(ip,threatMap){
  const d=threatMap[ip];
  if(!d)return null;
  const hasRestricted=d.hrPorts.size>0;
  const restrictedList=[...d.hrPorts].map(p=>p+'/'+(HIGH_RISK_PORTS[p]||'')).join(', ');
  const rejectPct=d.total?Math.round(d.rejected/d.total*100):0;
  const synPct=d.total?Math.round(d.synOnly/d.total*100):0;
  const topPorts=Object.entries(d.portCounts).sort((a,b)=>b[1]-a[1]).slice(0,5).map(([p])=>PORTS[p]?p+'/'+PORTS[p]:p).join(', ');
  return{ip,ports:d.ports.size,hrPorts:d.hrPorts.size,restrictedList,hasRestricted,rejected:d.rejected,total:d.total,rejectPct,synPct,topPorts};
}

// === RENDER ===
function render(){
  _btnId=0;
  const R=document.getElementById('results');
  const recs=applyFilters();
  const total=recs.length;
  const accepted=recs.filter(r=>r.action==='ACCEPT').length;
  const rejected=recs.filter(r=>r.action==='REJECT').length;
  const totalBytes=recs.reduce((s,r)=>s+r._bytes,0);
  const uniqueSrc=new Set(recs.map(r=>r.srcaddr)).size;
  const pubIPs=new Set(recs.filter(r=>!r._private).map(r=>r.srcaddr)).size;
  const starts=recs.map(r=>r._start).filter(t=>t>0);
  const ends=recs.map(r=>r._end).filter(t=>t>0);
  const minT=Math.min(...starts),maxT=Math.max(...ends);
  const timeRange=minT&&maxT?`${new Date(minT*1000).toISOString().slice(0,19)}Z → ${new Date(maxT*1000).toISOString().slice(0,19)}Z`:'Unknown';
  const rejectPct=total?Math.round(rejected/total*100):0;
  const countries=new Set(recs.filter(r=>!r._private).map(r=>{const g=geoFor(r.srcaddr);return g?g.country:'?';}).filter(c=>c!=='?')).size;

  // ENI / VPC / Subnet context
  const enis=[...new Set(recs.map(r=>r['interface-id']).filter(Boolean).filter(v=>v!=='-'))];
  const vpcs=[...new Set(recs.map(r=>r['vpc-id']).filter(Boolean).filter(v=>v!=='-'))];
  const subnets=[...new Set(recs.map(r=>r['subnet-id']).filter(Boolean).filter(v=>v!=='-'))];
  const accounts=[...new Set(recs.map(r=>r['account-id']).filter(Boolean).filter(v=>v!=='-'))];
  const privateIPs=[...new Set(recs.flatMap(r=>[r.srcaddr,r.dstaddr]).filter(ip=>isPrivate(ip)&&ip!=='0.0.0.0'))];

  // ENI filter options
  const eniList=[...new Set(recs.map(r=>r['interface-id']).filter(v=>v&&v!=='-'))];
  const eniOpts=eniList.map(e=>`<option value="${e}">${e}</option>`).join('');

  let html=`
  <div class="card" style="border-left-color:#0972d3">
    <b>${allRecords.length.toLocaleString()}</b> records parsed | Showing: <b>${total.toLocaleString()}</b> | Period: ${timeRange}<br>
    ${accounts.length?'<b>Account:</b> '+accounts.join(', ')+' | ':''}${vpcs.length?'<b>VPC:</b> '+vpcs.join(', ')+' | ':''}${subnets.length?'<b>Subnets:</b> '+subnets.join(', ')+' | ':''}${enis.length?'<b>ENIs:</b> '+enis.join(', '):''}
    ${privateIPs.length?'<br><b>Internal IPs:</b> '+privateIPs.slice(0,5).join(', ')+(privateIPs.length>5?' (+'+( privateIPs.length-5)+' more)':''):''}
  </div>
  <div class="filters" id="filterBar">
    <label>Action:</label><select id="fAction"><option value="all">All</option><option value="ACCEPT">Accept</option><option value="REJECT">Reject</option></select>
    <label>Protocol:</label><select id="fProto"><option value="all">All</option><option value="6">TCP</option><option value="17">UDP</option><option value="1">ICMP</option></select>
    <label>ENI:</label><select id="fEni"><option value="all">All ENIs</option>${eniOpts}</select>
    <label>Search IP:</label><input id="fSearch" placeholder="e.g. 10.0.1.">
    <button onclick="applyAndRender()">Apply</button>
    <button onclick="resetFilters()" style="background:#5f6b7a">Reset</button>
    <button id="resolveAllBtn" onclick="resolveAllGeo()" style="background:#ec7211">🌍 Resolve All GeoIP</button>
  </div>
  <div class="grid">
    <div class="s in"><div class="n">${total.toLocaleString()}</div><div class="l">Total Flows</div></div>
    <div class="s ok"><div class="n">${accepted.toLocaleString()}</div><div class="l">✅ Accepted</div></div>
    <div class="s cr"><div class="n">${rejected.toLocaleString()}</div><div class="l">❌ Rejected</div></div>
    <div class="s wa"><div class="n">${rejectPct}%</div><div class="l">Reject Rate</div></div>
    <div class="s in"><div class="n">${pubIPs.toLocaleString()}</div><div class="l">🌐 Public IPs</div></div>
    <div class="s wa"><div class="n">${countries}</div><div class="l">🌍 Countries</div></div>
    <div class="s in"><div class="n">${formatBytes(totalBytes)}</div><div class="l">Traffic</div></div>
  </div>`;
  html+=eniTable(recs);
  html+=threatTable(recs);
  html+=geoTable(recs);
  html+=topDestPorts(recs);
  html+=protocolBreakdown(recs);
  html+=timeline(recs);
  html+=topTalkers(recs);
  R.innerHTML=html;
  R.style.display='block';
  document.getElementById('loading').classList.remove('show');
  // Restore filter values
  document.getElementById('fAction').value=currentFilter.action;
  document.getElementById('fProto').value=currentFilter.protocol;
  document.getElementById('fEni').value=currentFilter.eni;
  document.getElementById('fSearch').value=currentFilter.search;
}

function applyFilters(){
  return allRecords.filter(r=>{
    if(currentFilter.action!=='all'&&r.action!==currentFilter.action)return false;
    if(currentFilter.protocol!=='all'&&r._protocol!==parseInt(currentFilter.protocol))return false;
    if(currentFilter.eni!=='all'&&r['interface-id']!==currentFilter.eni)return false;
    if(currentFilter.search&&!r.srcaddr.includes(currentFilter.search)&&!r.dstaddr.includes(currentFilter.search))return false;
    return true;
  });
}
function applyAndRender(){
  currentFilter.action=document.getElementById('fAction').value;
  currentFilter.protocol=document.getElementById('fProto').value;
  currentFilter.eni=document.getElementById('fEni').value;
  currentFilter.search=document.getElementById('fSearch').value;
  render();
}
function resetFilters(){currentFilter={action:'all',protocol:'all',search:'',eni:'all'};render();}

// === ENI BREAKDOWN ===
function eniTable(recs){
  const map={};
  recs.forEach(r=>{
    const eni=r['interface-id']||'unknown';
    if(eni==='-')return;
    if(!map[eni])map[eni]={inAccept:0,inReject:0,outAccept:0,outReject:0,bytesIn:0,bytesOut:0,srcIPs:new Set(),dstIPs:new Set(),privateIPs:new Set(),subnet:r['subnet-id']||'-'};
    const dir=r['flow-direction'];
    const isIngress=dir==='ingress'||(!dir&&!isPrivate(r.srcaddr));
    if(isIngress){
      r.action==='ACCEPT'?map[eni].inAccept++:map[eni].inReject++;
      map[eni].bytesIn+=r._bytes;
      map[eni].srcIPs.add(r.srcaddr);
    }else{
      r.action==='ACCEPT'?map[eni].outAccept++:map[eni].outReject++;
      map[eni].bytesOut+=r._bytes;
      map[eni].dstIPs.add(r.dstaddr);
    }
    // Track which private IPs are on this ENI
    [r.srcaddr,r.dstaddr].forEach(ip=>{if(isPrivate(ip)&&ip!=='0.0.0.0')map[eni].privateIPs.add(ip);});
  });
  const sorted=Object.entries(map).sort((a,b)=>(b[1].inAccept+b[1].inReject+b[1].outAccept+b[1].outReject)-(a[1].inAccept+a[1].inReject+a[1].outAccept+a[1].outReject));
  if(!sorted.length)return'';
  let html=`<h2>🔌 Network Interface (ENI) Breakdown</h2>
  <p class="sub">Traffic per ENI — shows which interface is the primary attack surface vs internal communication.</p>
  <div class="tw"><table><thead><tr><th>ENI</th><th>Private IP</th><th>Subnet</th><th>⬇ In Accept</th><th>⬇ In Reject</th><th>⬆ Out Accept</th><th>Bytes In</th><th>Bytes Out</th><th>Unique Sources</th></tr></thead><tbody>`;
  sorted.forEach(([eni,d])=>{
    const rejectPct=(d.inAccept+d.inReject)?Math.round(d.inReject/(d.inAccept+d.inReject)*100):0;
    html+=`<tr><td><b>${eni}</b></td><td>${[...d.privateIPs].join(', ')}</td><td>${d.subnet}</td>
    <td>${d.inAccept.toLocaleString()}</td><td>${d.inReject.toLocaleString()} <span class="t ${rejectPct>50?'cr':'ok'}">${rejectPct}%</span></td>
    <td>${d.outAccept.toLocaleString()}</td>
    <td>${formatBytes(d.bytesIn)}</td><td>${formatBytes(d.bytesOut)}</td>
    <td>${d.srcIPs.size.toLocaleString()}</td></tr>`;
  });
  return html+'</tbody></table></div>';
}

// === THREAT TABLE ===
function threatTable(recs){
  const threatMap=buildThreatData(recs);
  const pubSrcs=[...new Set(recs.filter(r=>!r._private).map(r=>r.srcaddr))];
  const scored=pubSrcs.map(ip=>scoreSrc(ip,threatMap)).filter(s=>s&&(s.hrPorts>0||s.ports>=3||s.rejected>0));
  // Sort: restricted ports first, then by total ports, then by rejected
  scored.sort((a,b)=>b.hrPorts-a.hrPorts||b.ports-a.ports||b.rejected-a.rejected);
  const top=scored.slice(0,30);
  if(!top.length)return'';
  let html=`<h2>🎯 Source IP Activity — <a href="https://docs.aws.amazon.com/config/latest/developerguide/restricted-common-ports.html">AWS Config Restricted Ports</a> Analysis</h2>
  <p class="sub">IPs that targeted ports flagged by AWS Config <code>restricted-common-ports</code> rule (20, 21, 22, 23, 3389, 3306, etc.) or contacted 3+ distinct ports. Data only — no severity assigned. For threat detection, enable <a href="https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html">Amazon GuardDuty</a>.</p>
  <div class="tw"><table><thead><tr><th>Source IP</th><th>Country</th><th>Org</th><th>Total Dest Ports</th><th>Top 5 Ports</th><th>Restricted Ports Hit</th><th>Flows</th><th>Rejected</th><th>Reject %</th><th>SYN-only %</th></tr></thead><tbody>`;
  top.forEach(s=>{
    const rCls=s.rejectPct>70?'cr':s.rejectPct>30?'wa':'ok';
    html+=`<tr>
    <td><b>${s.ip}</b></td><td>${ipGeoCell(s.ip)}</td><td>${ipOrgCell(s.ip)}</td>
    <td>${s.ports.toLocaleString()}</td>
    <td style="font-size:.75em;white-space:normal;max-width:200px">${s.topPorts}</td>
    <td>${s.hasRestricted?'<span class="t cr">'+s.restrictedList+'</span>':'—'}</td>
    <td>${s.total.toLocaleString()}</td><td>${s.rejected.toLocaleString()}</td>
    <td><span class="t ${rCls}">${s.rejectPct}%</span></td>
    <td>${s.synPct?s.synPct+'%':'—'}</td></tr>`;
  });
  return html+'</tbody></table></div>';
}

// === GEO TABLE ===
function geoTable(recs){
  const inbound=recs.filter(r=>!r._private);
  const map={};
  inbound.forEach(r=>{
    const g=geoFor(r.srcaddr);
    const k=g?g.cc+'|'+g.country:'??|Not resolved';
    if(!map[k])map[k]={country:g?g.country:'Not resolved',cc:g?g.cc:'??',accept:0,reject:0,ips:new Set()};
    r.action==='ACCEPT'?map[k].accept++:map[k].reject++;
    map[k].ips.add(r.srcaddr);
  });
  const sorted=Object.values(map).sort((a,b)=>(b.accept+b.reject)-(a.accept+a.reject));
  if(!sorted.length)return'';
  let html=`<h2>🌍 Geographic Distribution</h2>
  <div class="tw"><table><thead><tr><th>Country</th><th>Accepted</th><th>Unique IPs</th><th>Rejected</th><th>Reject Rate</th></tr></thead><tbody>`;
  sorted.forEach(d=>{
    const t=d.accept+d.reject;const rp=t?Math.round(d.reject/t*100):0;
    const cls=rp>70?'cr':rp>30?'wa':'ok';
    html+=`<tr><td>${flag(d.cc)} ${d.country}</td><td>${d.accept.toLocaleString()}</td><td>${d.ips.size}</td><td>${d.reject.toLocaleString()}</td><td><span class="t ${cls}">${rp}%</span></td></tr>`;
  });
  return html+'</tbody></table></div>';
}

// === TOP DEST PORTS ===
function topDestPorts(recs){
  const map={};
  recs.forEach(r=>{const p=r._dstport;if(!p)return;if(!map[p])map[p]={accept:0,reject:0};r.action==='ACCEPT'?map[p].accept++:map[p].reject++;});
  const sorted=Object.entries(map).sort((a,b)=>(b[1].accept+b[1].reject)-(a[1].accept+a[1].reject)).slice(0,20);
  let html=`<h2>🔌 Top Destination Ports</h2><div class="tw"><table><thead><tr><th>Port</th><th>Service</th><th>Accepted</th><th>Rejected</th><th>Total</th><th>Reject %</th></tr></thead><tbody>`;
  sorted.forEach(([port,d])=>{
    const t=d.accept+d.reject;const rp=t?Math.round(d.reject/t*100):0;const cls=rp>70?'cr':rp>30?'wa':'ok';
    html+=`<tr><td><b>${port}</b></td><td>${PORTS[port]||'—'}</td><td>${d.accept.toLocaleString()}</td><td>${d.reject.toLocaleString()}</td><td>${t.toLocaleString()}</td><td><span class="t ${cls}">${rp}%</span></td></tr>`;
  });
  return html+'</tbody></table></div>';
}

// === PROTOCOL BREAKDOWN ===
function protocolBreakdown(recs){
  const map={};
  recs.forEach(r=>{const p=r._protocol;if(!map[p])map[p]={accept:0,reject:0,bytes:0};r.action==='ACCEPT'?map[p].accept++:map[p].reject++;map[p].bytes+=r._bytes;});
  const sorted=Object.entries(map).sort((a,b)=>(b[1].accept+b[1].reject)-(a[1].accept+a[1].reject));
  let html=`<h2>📡 Protocol Distribution</h2><div class="tw"><table><thead><tr><th>Protocol</th><th>Accepted</th><th>Rejected</th><th>Reject %</th><th>Bytes</th></tr></thead><tbody>`;
  sorted.forEach(([proto,d])=>{
    const t=d.accept+d.reject;const rp=t?Math.round(d.reject/t*100):0;const cls=rp>70?'cr':rp>30?'wa':'ok';
    html+=`<tr><td><b>${PROTOS[proto]||'Proto '+proto}</b></td><td>${d.accept.toLocaleString()}</td><td>${d.reject.toLocaleString()}</td><td><span class="t ${cls}">${rp}%</span></td><td>${formatBytes(d.bytes)}</td></tr>`;
  });
  return html+'</tbody></table></div>';
}

// === TIMELINE ===
function timeline(recs){
  const map={};
  recs.forEach(r=>{if(!r._start)return;const h=new Date(r._start*1000).toISOString().slice(0,13)+':00';if(!map[h])map[h]={accept:0,reject:0};r.action==='ACCEPT'?map[h].accept++:map[h].reject++;});
  const sorted=Object.entries(map).sort((a,b)=>a[0].localeCompare(b[0]));
  if(!sorted.length)return'';
  const maxT=Math.max(...sorted.map(([,d])=>d.accept+d.reject));
  let html=`<h2>📊 Traffic Timeline (Hourly)</h2><div class="tw"><table><thead><tr><th>Hour (UTC)</th><th>Accepted</th><th>Rejected</th><th>Total</th><th>Distribution</th></tr></thead><tbody>`;
  sorted.forEach(([hour,d])=>{
    const t=d.accept+d.reject;const ap=maxT?Math.round(d.accept/maxT*100):0;const rp=maxT?Math.round(d.reject/maxT*100):0;
    html+=`<tr><td>${hour}</td><td>${d.accept.toLocaleString()}</td><td>${d.reject.toLocaleString()}</td><td>${t.toLocaleString()}</td>
    <td><div class="bar"><div class="fill" style="width:${ap}%;background:#037f0c"></div><div class="fill" style="width:${rp}%;background:#d13212"></div></div></td></tr>`;
  });
  return html+'</tbody></table></div>';
}

// === TOP TALKERS ===
function topTalkers(recs){
  const acc=recs.filter(r=>r.action==='ACCEPT');
  const map={};
  acc.forEach(r=>{if(!map[r.srcaddr])map[r.srcaddr]={flows:0,bytes:0};map[r.srcaddr].flows++;map[r.srcaddr].bytes+=r._bytes;});
  const sorted=Object.entries(map).sort((a,b)=>b[1].bytes-a[1].bytes).slice(0,20);
  if(!sorted.length)return'';
  let html=`<h2>📈 Top Talkers (by bytes)</h2><div class="tw"><table><thead><tr><th>Source IP</th><th>Country</th><th>Org</th><th>Flows</th><th>Bytes</th></tr></thead><tbody>`;
  sorted.forEach(([ip,d])=>{
    html+=`<tr><td><b>${ip}</b></td><td>${ipGeoCell(ip)}</td><td>${ipOrgCell(ip)}</td><td>${d.flows.toLocaleString()}</td><td>${formatBytes(d.bytes)}</td></tr>`;
  });
  return html+'</tbody></table></div>';
}
