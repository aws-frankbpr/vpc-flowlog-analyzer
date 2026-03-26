// === CONSTANTS ===
const PORTS={21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',135:'RPC',137:'NetBIOS',143:'IMAP',443:'HTTPS',445:'SMB',993:'IMAPS',1433:'MSSQL',1521:'Oracle',3306:'MySQL',3389:'RDP',5432:'PostgreSQL',5900:'VNC',6379:'Redis',8080:'HTTP-Alt',8443:'HTTPS-Alt',27017:'MongoDB'};
const PROTOS={1:'ICMP',6:'TCP',17:'UDP',47:'GRE',50:'ESP'};
const HIGH_RISK=[22,23,135,137,445,1433,3306,3389,5432,5900,6379,27017];
const V2_FIELDS=['version','account-id','interface-id','srcaddr','dstaddr','srcport','dstport','protocol','packets','bytes','start','end','action','log-status'];
const RFC1918=[{s:0x0A000000,m:0xFF000000},{s:0xAC100000,m:0xFFF00000},{s:0xC0A80000,m:0xFFFF0000}];

let allRecords=[], geoCache={}, currentFilter={action:'all',protocol:'all',search:''};

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
  document.getElementById('results').style.display='none';
  const reader=new FileReader();
  reader.onload=e=>setTimeout(()=>parseAndRender(e.target.result),50);
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
  // Collect unique public IPs for GeoIP (both src and dst)
  const pubIPs=[...new Set(allRecords.flatMap(r=>[r.srcaddr,r.dstaddr]).filter(ip=>!isPrivate(ip)))];
  // Show results immediately, then enrich with GeoIP
  render();
  if(pubIPs.length>0){
    document.getElementById('loading').innerHTML=`⏳ Enriching ${pubIPs.length} IPs with GeoIP... <button onclick="skipGeo()" style="margin-left:12px;padding:4px 12px;background:#5f6b7a;color:#fff;border:none;border-radius:4px;cursor:pointer">Skip GeoIP</button>`;
    document.getElementById('loading').classList.add('show');
    window._skipGeo=false;
    lookupGeo(pubIPs).then(()=>{if(!window._skipGeo)render();});
  }
}

function showError(msg){
  document.getElementById('loading').classList.remove('show');
  document.getElementById('results').style.display='block';
  document.getElementById('results').innerHTML=`<div class="card" style="border-left-color:#d13212"><b>Error:</b> ${msg}</div>`;
}
function skipGeo(){window._skipGeo=true;document.getElementById('loading').classList.remove('show');}

// === GEOIP LOOKUP (ip-api.com batch via HTTP — 100 IPs per request) ===
async function lookupGeo(ips){
  document.getElementById('loading').innerHTML='⏳ Looking up GeoIP for '+ips.length+' public IPs...';
  // ip-api.com batch: 100 per request, 15 req/min on free tier (HTTP only)
  // Try batch first, fallback to ipwho.is for remaining
  const batches=[];
  for(let i=0;i<ips.length;i+=100)batches.push(ips.slice(i,i+100));
  let done=0;
  for(const batch of batches){
    try{
      const resp=await fetch('http://ip-api.com/batch?fields=status,query,country,countryCode,org,isp',{
        method:'POST',body:JSON.stringify(batch)
      });
      const data=await resp.json();
      data.forEach(d=>{if(d.status==='success')geoCache[d.query]={country:d.country,cc:d.countryCode,org:d.org||d.isp||'Unknown'};});
    }catch(e){
      // HTTP blocked on HTTPS page — fallback: resolve in parallel via ipwho.is
      await Promise.all(batch.map(async ip=>{
        try{
          const r=await fetch('https://ipwho.is/'+ip);
          const d=await r.json();
          if(d.success!==false)geoCache[ip]={country:d.country||'Unknown',cc:d.country_code||'??',org:d.connection?.org||d.connection?.isp||'Unknown'};
        }catch(e2){}
      }));
    }
    done+=batch.length;
    document.getElementById('loading').innerHTML='⏳ GeoIP: '+done+'/'+ips.length+' IPs...';
    if(batches.length>15)await new Promise(r=>setTimeout(r,4200)); // rate limit
  }
}

function geoFor(ip){
  if(isPrivate(ip))return{country:'Private',cc:'🏠',org:'RFC1918'};
  return geoCache[ip]||{country:'Unknown',cc:'??',org:'Unknown'};
}
function flag(cc){
  if(cc==='🏠')return'🏠';if(!cc||cc==='??')return'🌐';
  return String.fromCodePoint(...[...cc.toUpperCase()].map(c=>0x1F1E6+c.charCodeAt(0)-65));
}

// === THREAT SCORING ===
function scoreSrc(ip,records){
  const flows=records.filter(r=>r.srcaddr===ip);
  const ports=new Set(flows.map(r=>r._dstport));
  const rejected=flows.filter(r=>r.action==='REJECT').length;
  const total=flows.length;
  const hrPorts=[...ports].filter(p=>HIGH_RISK.includes(p)).length;
  const synOnly=flows.filter(r=>r._tcpflags===2).length;
  let score=0;
  if(ports.size>=6)score+=40;else if(ports.size>=3)score+=20;
  if(hrPorts>=3)score+=25;else if(hrPorts>=1)score+=10;
  if(total>0&&rejected/total>0.8)score+=20;
  if(synOnly>0&&synOnly/total>0.7)score+=15;
  score=Math.min(score,100);
  let label='🟢 NORMAL',cls='ok';
  if(score>=70){label='🔴 PORT SCANNER';cls='cr';}
  else if(score>=50){label='🟠 SUSPICIOUS';cls='wa';}
  else if(score>=30){label='🟡 MONITOR';cls='wa';}
  return{score,label,cls,ports:ports.size,rejected,total,hrPorts,synOnly};
}

// === RENDER ===
function render(){
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
  const countries=new Set(recs.filter(r=>!r._private).map(r=>geoFor(r.srcaddr).country)).size;

  // ENI / VPC / Subnet context
  const enis=[...new Set(recs.map(r=>r['interface-id']).filter(Boolean).filter(v=>v!=='-'))];
  const vpcs=[...new Set(recs.map(r=>r['vpc-id']).filter(Boolean).filter(v=>v!=='-'))];
  const subnets=[...new Set(recs.map(r=>r['subnet-id']).filter(Boolean).filter(v=>v!=='-'))];
  const accounts=[...new Set(recs.map(r=>r['account-id']).filter(Boolean).filter(v=>v!=='-'))];
  const privateIPs=[...new Set(recs.flatMap(r=>[r.srcaddr,r.dstaddr]).filter(ip=>isPrivate(ip)&&ip!=='0.0.0.0'))];

  let html=`
  <div class="card" style="border-left-color:#0972d3">
    <b>${allRecords.length.toLocaleString()}</b> records parsed | Showing: <b>${total.toLocaleString()}</b> | Period: ${timeRange}<br>
    ${accounts.length?'<b>Account:</b> '+accounts.join(', ')+' | ':''}${vpcs.length?'<b>VPC:</b> '+vpcs.join(', ')+' | ':''}${subnets.length?'<b>Subnets:</b> '+subnets.join(', ')+' | ':''}${enis.length?'<b>ENIs:</b> '+enis.join(', '):''}
    ${privateIPs.length?'<br><b>Internal IPs:</b> '+privateIPs.slice(0,5).join(', ')+(privateIPs.length>5?' (+'+( privateIPs.length-5)+' more)':''):''}
  </div>
  <div class="filters" id="filterBar">
    <label>Action:</label><select id="fAction"><option value="all">All</option><option value="ACCEPT">Accept</option><option value="REJECT">Reject</option></select>
    <label>Protocol:</label><select id="fProto"><option value="all">All</option><option value="6">TCP</option><option value="17">UDP</option><option value="1">ICMP</option></select>
    <label>Search IP:</label><input id="fSearch" placeholder="e.g. 10.0.1.">
    <button onclick="applyAndRender()">Apply</button>
    <button onclick="resetFilters()" style="background:#5f6b7a">Reset</button>
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
  document.getElementById('fSearch').value=currentFilter.search;
}

function applyFilters(){
  return allRecords.filter(r=>{
    if(currentFilter.action!=='all'&&r.action!==currentFilter.action)return false;
    if(currentFilter.protocol!=='all'&&r._protocol!==parseInt(currentFilter.protocol))return false;
    if(currentFilter.search&&!r.srcaddr.includes(currentFilter.search)&&!r.dstaddr.includes(currentFilter.search))return false;
    return true;
  });
}
function applyAndRender(){
  currentFilter.action=document.getElementById('fAction').value;
  currentFilter.protocol=document.getElementById('fProto').value;
  currentFilter.search=document.getElementById('fSearch').value;
  render();
}
function resetFilters(){currentFilter={action:'all',protocol:'all',search:''};render();}

// === THREAT TABLE ===
function threatTable(recs){
  const pubSrcs=[...new Set(recs.filter(r=>!r._private).map(r=>r.srcaddr))];
  const scored=pubSrcs.map(ip=>{const s=scoreSrc(ip,recs);const g=geoFor(ip);return{ip,...s,...g};}).filter(s=>s.score>=30).sort((a,b)=>b.score-a.score).slice(0,25);
  if(!scored.length)return'';
  let html=`<h2>🎯 Top Threat Sources — Ranked by Threat Score</h2>
  <p class="sub">Scored 0-100 based on: ports targeted, high-risk ports hit, reject ratio, SYN-only patterns.</p>
  <div class="tw"><table><thead><tr><th>Score</th><th>Threat</th><th>Source IP</th><th>Country</th><th>Org</th><th>Ports Hit</th><th>High-Risk</th><th>Flows</th><th>Rejected</th></tr></thead><tbody>`;
  scored.forEach(s=>{
    html+=`<tr><td><span class="t ${s.cls}">${s.score}</span></td><td><span class="t ${s.cls}">${s.label}</span></td>
    <td><b>${s.ip}</b></td><td>${flag(s.cc)} ${s.country}</td><td>${s.org}</td>
    <td>${s.ports}</td><td>${s.hrPorts}</td><td>${s.total.toLocaleString()}</td><td>${s.rejected.toLocaleString()}</td></tr>`;
  });
  return html+'</tbody></table></div>';
}

// === GEO TABLE ===
function geoTable(recs){
  const inbound=recs.filter(r=>!r._private);
  const map={};
  inbound.forEach(r=>{
    const g=geoFor(r.srcaddr);
    const k=g.cc+'|'+g.country;
    if(!map[k])map[k]={country:g.country,cc:g.cc,accept:0,reject:0,ips:new Set()};
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
    const g=geoFor(ip);
    html+=`<tr><td><b>${ip}</b></td><td>${flag(g.cc)} ${g.country}</td><td>${g.org}</td><td>${d.flows.toLocaleString()}</td><td>${formatBytes(d.bytes)}</td></tr>`;
  });
  return html+'</tbody></table></div>';
}
