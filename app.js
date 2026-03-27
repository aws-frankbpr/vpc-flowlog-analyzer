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
// Resolve only IPs shown in top 20 tables
async function resolveAllGeo(){
  const recs=applyFilters();
  const inbound=recs.filter(r=>isInbound(r));
  const outbound=recs.filter(r=>!isInbound(r));
  // Collect top inbound source IPs
  const inMap={};
  inbound.forEach(r=>{inMap[r.srcaddr]=(inMap[r.srcaddr]||0)+1;});
  const inTopIPs=Object.entries(inMap).sort((a,b)=>b[1]-a[1]).slice(0,20).map(([ip])=>ip);
  // Collect top outbound dest IPs
  const outMap={};
  outbound.forEach(r=>{outMap[r.dstaddr]=(outMap[r.dstaddr]||0)+r._bytes;});
  const outTopIPs=Object.entries(outMap).sort((a,b)=>b[1]-a[1]).slice(0,20).map(([ip])=>ip);
  const allTableIPs=[...new Set([...inTopIPs,...outTopIPs])].filter(ip=>!isPrivate(ip)&&!geoCache[ip]);
  if(!allTableIPs.length){alert('All visible IPs already resolved!');return}
  const btn=document.getElementById('resolveAllBtn');
  if(btn){btn.disabled=true;btn.textContent=`⏳ Resolving ${allTableIPs.length} IPs...`;}
  const batches=[];
  for(let i=0;i<allTableIPs.length;i+=100)batches.push(allTableIPs.slice(i,i+100));
  for(const batch of batches){
    try{
      const r=await fetch('https://corsproxy.io/?url='+encodeURIComponent('http://ip-api.com/batch?fields=status,query,country,countryCode,org,isp'),{
        method:'POST',body:JSON.stringify(batch)
      });
      const data=await r.json();
      data.forEach(d=>{if(d.status==='success')geoCache[d.query]={country:d.country,cc:d.countryCode,org:d.org||d.isp||'Unknown'};});
    }catch(e){}
  }
  if(btn){btn.disabled=false;btn.textContent='🌍 Resolve GeoIP';}
  render();
}

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
  return'—';
}
function ipOrgCell(ip){
  const g=geoFor(ip);
  return g?g.org:'—';
}

// AWS Config restricted-common-ports reference:
// https://docs.aws.amazon.com/config/latest/developerguide/restricted-common-ports.html
const HIGH_RISK_PORTS={20:'FTP-Data',21:'FTP',22:'SSH',23:'Telnet',135:'RPC',137:'NetBIOS',445:'SMB',1433:'MSSQL',3306:'MySQL',3389:'RDP',4333:'Reserved',5432:'PostgreSQL',5900:'VNC',6379:'Redis',27017:'MongoDB'};

// === CLASSIFY DIRECTION ===
function isInbound(r){
  if(r['flow-direction']==='ingress')return true;
  if(r['flow-direction']==='egress')return false;
  return !isPrivate(r.srcaddr); // no direction field: public src = inbound
}

// === RENDER ===
function render(){
  const R=document.getElementById('results');
  const recs=applyFilters();
  const inbound=recs.filter(r=>isInbound(r));
  const outbound=recs.filter(r=>!isInbound(r));
  const total=recs.length;
  const starts=recs.map(r=>r._start).filter(t=>t>0);
  const ends=recs.map(r=>r._end).filter(t=>t>0);
  const minT=Math.min(...starts),maxT=Math.max(...ends);
  const timeRange=minT&&maxT?`${new Date(minT*1000).toISOString().slice(0,19)}Z → ${new Date(maxT*1000).toISOString().slice(0,19)}Z`:'Unknown';

  const enis=[...new Set(recs.map(r=>r['interface-id']).filter(Boolean).filter(v=>v!=='-'))];
  const vpcs=[...new Set(recs.map(r=>r['vpc-id']).filter(Boolean).filter(v=>v!=='-'))];
  const subnets=[...new Set(recs.map(r=>r['subnet-id']).filter(Boolean).filter(v=>v!=='-'))];
  const accounts=[...new Set(recs.map(r=>r['account-id']).filter(Boolean).filter(v=>v!=='-'))];
  const privateIPs=[...new Set(recs.flatMap(r=>[r.srcaddr,r.dstaddr]).filter(ip=>isPrivate(ip)&&ip!=='0.0.0.0'))];
  const eniList=[...new Set(recs.map(r=>r['interface-id']).filter(v=>v&&v!=='-'))];
  const eniOpts=eniList.map(e=>`<option value="${e}">${e}</option>`).join('');

  let html=`
  <div class="card" style="border-left-color:#0972d3">
    <b>${allRecords.length.toLocaleString()}</b> records parsed | Showing: <b>${total.toLocaleString()}</b> (⬇ ${inbound.length.toLocaleString()} inbound, ⬆ ${outbound.length.toLocaleString()} outbound) | Period: ${timeRange}<br>
    ${accounts.length?'<b>Account:</b> '+accounts.join(', ')+' | ':''}${vpcs.length?'<b>VPC:</b> '+vpcs.join(', ')+' | ':''}${subnets.length?'<b>Subnets:</b> '+subnets.join(', ')+' | ':''}${enis.length?'<b>ENIs:</b> '+enis.join(', '):''}
    ${privateIPs.length?'<br><b>Internal IPs:</b> '+privateIPs.slice(0,5).join(', ')+(privateIPs.length>5?' (+'+(privateIPs.length-5)+' more)':''):''}
  </div>
  <div class="filters" id="filterBar">
    <label>Action:</label><select id="fAction"><option value="all">All</option><option value="ACCEPT">Accept</option><option value="REJECT">Reject</option></select>
    <label>Protocol:</label><select id="fProto"><option value="all">All</option><option value="6">TCP</option><option value="17">UDP</option><option value="1">ICMP</option></select>
    <label>ENI:</label><select id="fEni"><option value="all">All ENIs</option>${eniOpts}</select>
    <label>Search IP:</label><input id="fSearch" placeholder="e.g. 10.0.1.">
    <button onclick="applyAndRender()">Apply</button>
    <button onclick="resetFilters()" style="background:#5f6b7a">Reset</button>
    <button id="resolveAllBtn" onclick="resolveAllGeo()" style="background:#ec7211">🌍 Resolve GeoIP</button>
  </div>`;

  html+=eniTable(recs);

  // === INBOUND SECTION ===
  html+=`<h2 style="color:#0972d3;font-size:1.3em;border-bottom:3px solid #0972d3">⬇ Inbound Traffic (${inbound.length.toLocaleString()} flows, ${formatBytes(inbound.reduce((s,r)=>s+r._bytes,0))})</h2>`;
  html+=summaryGrid(inbound);
  html+=topSourceIPs(inbound);
  html+=topPorts(inbound,'dstport','Top Inbound Destination Ports');
  html+=geoTable(inbound,'srcaddr');
  html+=protocolBreakdown(inbound);

  // === OUTBOUND SECTION ===
  html+=`<h2 style="color:#ec7211;font-size:1.3em;border-bottom:3px solid #ec7211">⬆ Outbound Traffic (${outbound.length.toLocaleString()} flows, ${formatBytes(outbound.reduce((s,r)=>s+r._bytes,0))})</h2>`;
  html+=summaryGrid(outbound);
  html+=topDestIPs(outbound);
  html+=topPorts(outbound,'dstport','Top Outbound Destination Ports');
  html+=geoTable(outbound,'dstaddr');
  html+=protocolBreakdown(outbound);

  // === COMBINED ===
  html+=`<h2 style="font-size:1.3em;border-bottom:3px solid #5f6b7a">📊 Combined Timeline</h2>`;
  html+=timeline(recs);

  R.innerHTML=html;
  R.style.display='block';
  document.getElementById('loading').classList.remove('show');
  document.getElementById('fAction').value=currentFilter.action;
  document.getElementById('fProto').value=currentFilter.protocol;
  document.getElementById('fEni').value=currentFilter.eni;
  document.getElementById('fSearch').value=currentFilter.search;
}

// === SUMMARY GRID (reusable) ===
function summaryGrid(recs){
  const accepted=recs.filter(r=>r.action==='ACCEPT').length;
  const rejected=recs.filter(r=>r.action==='REJECT').length;
  const rejectPct=recs.length?Math.round(rejected/recs.length*100):0;
  const bytes=recs.reduce((s,r)=>s+r._bytes,0);
  const uniqueIPs=new Set(recs.map(r=>r.srcaddr)).size;
  return`<div class="grid">
    <div class="s in"><div class="n">${recs.length.toLocaleString()}</div><div class="l">Flows</div></div>
    <div class="s ok"><div class="n">${accepted.toLocaleString()}</div><div class="l">✅ Accepted</div></div>
    <div class="s cr"><div class="n">${rejected.toLocaleString()}</div><div class="l">❌ Rejected</div></div>
    <div class="s wa"><div class="n">${rejectPct}%</div><div class="l">Reject Rate</div></div>
    <div class="s in"><div class="n">${uniqueIPs.toLocaleString()}</div><div class="l">Unique IPs</div></div>
    <div class="s in"><div class="n">${formatBytes(bytes)}</div><div class="l">Traffic</div></div>
  </div>`;
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

// === TOP INBOUND SOURCE IPs (combined: bytes + ports + restricted) ===
function topSourceIPs(recs){
  const map={};
  recs.forEach(r=>{
    const ip=r.srcaddr;
    if(!map[ip])map[ip]={bytes:0,flows:0,accepted:0,rejected:0,ports:new Set(),hrPorts:new Set(),synOnly:0};
    const d=map[ip];
    d.flows++;d.bytes+=r._bytes;
    r.action==='ACCEPT'?d.accepted++:d.rejected++;
    d.ports.add(r._dstport);
    if(HIGH_RISK_PORTS[r._dstport])d.hrPorts.add(r._dstport);
    if(r._tcpflags===2)d.synOnly++;
  });
  const sorted=Object.entries(map).sort((a,b)=>b[1].flows-a[1].flows).slice(0,20);
  if(!sorted.length)return'';
  let html=`<h3>🎯 Top 20 Inbound Source IPs — of ${Object.keys(map).length} (<a href="https://docs.aws.amazon.com/config/latest/developerguide/restricted-common-ports.html">AWS Config Restricted Ports</a> flagged)</h3>
  <div class="tw"><table><thead><tr><th>Source IP</th><th>Country</th><th>Org</th><th>Flows</th><th>Accepted</th><th>Rejected</th><th>Bytes</th><th>Unique Ports</th><th>Restricted Ports Hit</th><th>SYN-only %</th></tr></thead><tbody>`;
  sorted.forEach(([ip,d])=>{
    const rp=d.flows?Math.round(d.rejected/d.flows*100):0;
    const sp=d.flows?Math.round(d.synOnly/d.flows*100):0;
    const rList=[...d.hrPorts].map(p=>p+'/'+(HIGH_RISK_PORTS[p]||'')).join(', ');
    html+=`<tr><td><b>${ip}</b></td><td>${ipGeoCell(ip)}</td><td>${ipOrgCell(ip)}</td>
    <td>${d.flows.toLocaleString()}</td><td>${d.accepted.toLocaleString()}</td><td>${d.rejected.toLocaleString()}</td>
    <td>${formatBytes(d.bytes)}</td><td>${d.ports.size.toLocaleString()}</td>
    <td>${d.hrPorts.size?'<span class="t cr">'+rList+'</span>':'—'}</td>
    <td>${sp?sp+'%':'—'}</td></tr>`;
  });
  return html+'</tbody></table></div>';
}

// === TOP OUTBOUND DESTINATION IPs (exclude ENI's own IPs) ===
function topDestIPs(recs){
  // Detect IPs that belong to ENIs in this flow log:
  // In egress flows, srcaddr is the ENI's IP. In ingress flows, dstaddr is the ENI's IP.
  const eniIPs=new Set();
  allRecords.forEach(r=>{
    const dir=r['flow-direction'];
    if(dir==='egress')eniIPs.add(r.srcaddr);
    else if(dir==='ingress')eniIPs.add(r.dstaddr);
  });
  // Fallback if no flow-direction field: use private IPs seen in both src and dst
  if(!eniIPs.size){
    const srcs=new Set(allRecords.map(r=>r.srcaddr).filter(isPrivate));
    const dsts=new Set(allRecords.map(r=>r.dstaddr).filter(isPrivate));
    srcs.forEach(ip=>{if(dsts.has(ip))eniIPs.add(ip);});
  }
  const map={};
  recs.forEach(r=>{
    const ip=r.dstaddr;
    if(eniIPs.has(ip))return; // Skip traffic to own ENI IPs
    if(!map[ip])map[ip]={bytes:0,flows:0,accepted:0,rejected:0,ports:new Set(),priv:isPrivate(ip)};
    const d=map[ip];
    d.flows++;d.bytes+=r._bytes;
    r.action==='ACCEPT'?d.accepted++:d.rejected++;
    d.ports.add(r._dstport);
  });
  const sorted=Object.entries(map).sort((a,b)=>b[1].bytes-a[1].bytes).slice(0,20);
  if(!sorted.length)return'';
  let html=`<h3>🎯 Top 20 Outbound Destination IPs — of ${Object.keys(map).length}</h3>
  <p class="sub">Traffic to this ENI's own IPs excluded (${[...eniIPs].join(', ')}). Private IPs may indicate cross-subnet or cross-VPC communication.</p>
  <div class="tw"><table><thead><tr><th>Destination IP</th><th>Country</th><th>Org</th><th>Flows</th><th>Accepted</th><th>Rejected</th><th>Bytes</th><th>Unique Ports</th></tr></thead><tbody>`;
  sorted.forEach(([ip,d])=>{
    html+=`<tr><td><b>${ip}</b> ${d.priv?'<span class="t in">VPC</span>':''}</td><td>${ipGeoCell(ip)}</td><td>${ipOrgCell(ip)}</td>
    <td>${d.flows.toLocaleString()}</td><td>${d.accepted.toLocaleString()}</td><td>${d.rejected.toLocaleString()}</td>
    <td>${formatBytes(d.bytes)}</td><td>${d.ports.size.toLocaleString()}</td></tr>`;
  });
  return html+'</tbody></table></div>';
}

// === GEO TABLE (reusable, ipField = which field to geolocate) ===
function geoTable(recs,ipField){
  const map={};
  recs.forEach(r=>{
    const ip=r[ipField];
    if(isPrivate(ip))return;
    const g=geoFor(ip);
    const k=g?g.cc+'|'+g.country:'??|Not resolved';
    if(!map[k])map[k]={country:g?g.country:'Not resolved',cc:g?g.cc:'??',accept:0,reject:0,ips:new Set()};
    r.action==='ACCEPT'?map[k].accept++:map[k].reject++;
    map[k].ips.add(ip);
  });
  const sorted=Object.values(map).sort((a,b)=>(b.accept+b.reject)-(a.accept+a.reject));
  const top=sorted.slice(0,20);
  if(!top.length)return'';
  let html=`<h3>🌍 Geographic Distribution — Top 20 of ${sorted.length}</h3>
  <div class="tw"><table><thead><tr><th>Country</th><th>Accepted</th><th>Unique IPs</th><th>Rejected</th><th>Reject Rate</th></tr></thead><tbody>`;
  top.forEach(d=>{
    const t=d.accept+d.reject;const rp=t?Math.round(d.reject/t*100):0;
    const cls=rp>70?'cr':rp>30?'wa':'ok';
    html+=`<tr><td>${flag(d.cc)} ${d.country}</td><td>${d.accept.toLocaleString()}</td><td>${d.ips.size}</td><td>${d.reject.toLocaleString()}</td><td><span class="t ${cls}">${rp}%</span></td></tr>`;
  });
  return html+'</tbody></table></div>';
}

// === TOP PORTS (reusable) ===
function topPorts(recs,portField,title){
  const map={};
  recs.forEach(r=>{const p=parseInt(r[portField])||0;if(!p)return;if(!map[p])map[p]={accept:0,reject:0};r.action==='ACCEPT'?map[p].accept++:map[p].reject++;});
  const sorted=Object.entries(map).sort((a,b)=>(b[1].accept+b[1].reject)-(a[1].accept+a[1].reject));
  const top=sorted.slice(0,20);
  if(!top.length)return'';
  let html=`<h3>🔌 ${title} — Top 20 of ${sorted.length}</h3><div class="tw"><table><thead><tr><th>Port</th><th>Service</th><th>Accepted</th><th>Rejected</th><th>Total</th><th>Reject %</th></tr></thead><tbody>`;
  top.forEach(([port,d])=>{
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

// (old topIPs/topTalkers replaced by topSourceIPs/topDestIPs)
