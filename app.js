// === CONSTANTS ===
const PORTS={21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',135:'RPC',137:'NetBIOS',143:'IMAP',443:'HTTPS',445:'SMB',993:'IMAPS',1433:'MSSQL',1521:'Oracle',3306:'MySQL',3389:'RDP',5432:'PostgreSQL',5900:'VNC',6379:'Redis',8080:'HTTP-Alt',8443:'HTTPS-Alt',27017:'MongoDB'};
const PROTOS={1:'ICMP',6:'TCP',17:'UDP',47:'GRE',50:'ESP'};
const V2_FIELDS=['version','account-id','interface-id','srcaddr','dstaddr','srcport','dstport','protocol','packets','bytes','start','end','action','log-status'];
const RFC1918=[{s:0x0A000000,m:0xFF000000},{s:0xAC100000,m:0xFFF00000},{s:0xC0A80000,m:0xFFFF0000}];
const HIGH_RISK_PORTS={20:'FTP-Data',21:'FTP',22:'SSH',23:'Telnet',135:'RPC',137:'NetBIOS',445:'SMB',1433:'MSSQL',3306:'MySQL',3389:'RDP',4333:'Reserved',5432:'PostgreSQL',5900:'VNC',6379:'Redis',27017:'MongoDB'};

let allRecords=[], geoCache={}, currentFilter={action:'all',protocol:'all',search:'',eni:'all',port:''};

// === THEME ===
function toggleTheme(){
  const d=document.documentElement;
  const next=d.getAttribute('data-theme')==='dark'?'light':'dark';
  d.setAttribute('data-theme',next);
  localStorage.setItem('theme',next);
  document.getElementById('themeBtn').textContent=next==='dark'?'☀️':'🌙';
}
(function(){
  const saved=localStorage.getItem('theme')||(window.matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light');
  if(saved==='dark'){document.documentElement.setAttribute('data-theme','dark');document.addEventListener('DOMContentLoaded',()=>{const b=document.getElementById('themeBtn');if(b)b.textContent='☀️';});}
})();

// === BACK TO TOP ===
window.addEventListener('scroll',()=>{
  const btn=document.getElementById('backToTop');
  if(btn)btn.classList.toggle('show',window.scrollY>400);
});

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
  const loading=document.getElementById('loading');
  const pFill=document.getElementById('progressFill');
  loading.classList.add('show');
  loading.querySelector('span')||loading.insertAdjacentHTML('afterbegin','<span></span>');
  const span=loading.querySelector('span')||loading;
  span.textContent=`⏳ Reading ${(file.size/1048576).toFixed(1)} MB...`;
  pFill.style.width='10%';
  document.getElementById('results').style.display='none';
  const reader=new FileReader();
  reader.onprogress=e=>{if(e.lengthComputable)pFill.style.width=Math.round(e.loaded/e.total*40)+'%';};
  reader.onload=e=>{
    span.textContent='⏳ Parsing flow log records...';
    pFill.style.width='50%';
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
  const pFill=document.getElementById('progressFill');
  const lines=text.trim().split('\n').filter(l=>l.trim());
  if(lines.length<2){showError('File has fewer than 2 lines');return}
  const det=detectFields(lines[0]);
  if(!det){showError('Could not detect flow log format');return}
  const{fields,isCSV}=det;
  const hasHeader=isCSV||fields!==V2_FIELDS||lines[0].includes('version');
  const dataLines=hasHeader?lines.slice(1):lines;
  allRecords=[];
  pFill.style.width='60%';
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
  pFill.style.width='80%';
  // Shrink dropzone for re-upload
  const dz=document.getElementById('dropzone');
  dz.classList.add('mini');
  document.querySelector('.privacy').style.display='none';
  document.getElementById('exportBtn').classList.add('show');
  setTimeout(()=>{pFill.style.width='100%';setTimeout(()=>render(),50);},50);
}

function showError(msg){
  document.getElementById('loading').classList.remove('show');
  document.getElementById('results').style.display='block';
  document.getElementById('results').innerHTML=`<div class="card" style="border-left-color:var(--danger)"><b>Error:</b> ${msg}</div>`;
}

// === GEOIP ===
async function resolveAllGeo(){
  const recs=applyFilters();
  const inbound=recs.filter(r=>isInbound(r));
  const outbound=recs.filter(r=>!isInbound(r));
  const inMap={};
  inbound.forEach(r=>{inMap[r.srcaddr]=(inMap[r.srcaddr]||0)+1;});
  const inTopIPs=Object.entries(inMap).sort((a,b)=>b[1]-a[1]).slice(0,20).map(([ip])=>ip);
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
function ipGeoCell(ip){const g=geoFor(ip);return g?`${flag(g.cc)} ${g.country}`:'—';}
function ipOrgCell(ip){const g=geoFor(ip);return g?g.org:'—';}

// === TABLE SORTING ===
function makeSortable(){
  document.querySelectorAll('.tw table').forEach(table=>{
    table.querySelectorAll('th').forEach((th,colIdx)=>{
      if(th.dataset.sortBound)return;
      th.dataset.sortBound='1';
      th.innerHTML+=` <span class="sort-arrow">↕</span>`;
      th.addEventListener('click',()=>{
        const tbody=table.querySelector('tbody');
        if(!tbody)return;
        const rows=[...tbody.querySelectorAll('tr')];
        const asc=th.dataset.sort!=='asc';
        table.querySelectorAll('th').forEach(h=>{h.classList.remove('sorted');h.dataset.sort='';});
        th.classList.add('sorted');
        th.dataset.sort=asc?'asc':'desc';
        rows.sort((a,b)=>{
          const ac=a.cells[colIdx],bc=b.cells[colIdx];
          if(!ac||!bc)return 0;
          const av=ac.textContent.trim(),bv=bc.textContent.trim();
          const an=parseFloat(av.replace(/[,%]/g,'')),bn=parseFloat(bv.replace(/[,%]/g,''));
          if(!isNaN(an)&&!isNaN(bn))return asc?an-bn:bn-an;
          return asc?av.localeCompare(bv):bv.localeCompare(av);
        });
        rows.forEach(r=>tbody.appendChild(r));
      });
    });
  });
}

// === CLASSIFY DIRECTION ===
function isInbound(r){
  if(r['flow-direction']==='ingress')return true;
  if(r['flow-direction']==='egress')return false;
  return !isPrivate(r.srcaddr);
}

// === FILTERS ===
function applyFilters(){
  return allRecords.filter(r=>{
    if(currentFilter.action!=='all'&&r.action!==currentFilter.action)return false;
    if(currentFilter.protocol!=='all'&&r._protocol!==parseInt(currentFilter.protocol))return false;
    if(currentFilter.eni!=='all'&&r['interface-id']!==currentFilter.eni)return false;
    if(currentFilter.search&&!r.srcaddr.includes(currentFilter.search)&&!r.dstaddr.includes(currentFilter.search))return false;
    if(currentFilter.port&&r._srcport!==parseInt(currentFilter.port)&&r._dstport!==parseInt(currentFilter.port))return false;
    return true;
  });
}
function applyAndRender(){
  currentFilter.action=document.getElementById('fAction').value;
  currentFilter.protocol=document.getElementById('fProto').value;
  currentFilter.eni=document.getElementById('fEni').value;
  currentFilter.search=document.getElementById('fSearch').value;
  currentFilter.port=document.getElementById('fPort').value.trim();
  render();
}
function resetFilters(){currentFilter={action:'all',protocol:'all',search:'',eni:'all',port:''};render();}

function filterByPort(port){
  currentFilter.port=String(port);
  render();
  window.scrollTo({top:0,behavior:'smooth'});
}

// === EXPORT ===
function exportCSV(){
  const recs=applyFilters();
  if(!recs.length){alert('No records to export');return}
  const inbound=recs.filter(r=>isInbound(r));
  const outbound=recs.filter(r=>!isInbound(r));
  let csv='VPC Flow Log Analysis Summary\n';
  csv+=`Total Records,${recs.length}\nInbound Flows,${inbound.length}\nOutbound Flows,${outbound.length}\n`;
  csv+=`Accepted,${recs.filter(r=>r.action==='ACCEPT').length}\nRejected,${recs.filter(r=>r.action==='REJECT').length}\n`;
  csv+=`Total Bytes,${recs.reduce((s,r)=>s+r._bytes,0)}\n\n`;
  csv+='Top Inbound Source IPs\nIP,Flows,Accepted,Rejected,Bytes\n';
  const srcMap={};
  inbound.forEach(r=>{if(!srcMap[r.srcaddr])srcMap[r.srcaddr]={f:0,a:0,rj:0,b:0};const d=srcMap[r.srcaddr];d.f++;d.b+=r._bytes;r.action==='ACCEPT'?d.a++:d.rj++;});
  Object.entries(srcMap).sort((a,b)=>b[1].f-a[1].f).slice(0,20).forEach(([ip,d])=>{csv+=`${ip},${d.f},${d.a},${d.rj},${d.b}\n`;});
  const blob=new Blob([csv],{type:'text/csv'});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download='flowlog-analysis.csv';
  a.click();
}

// === RENDER ===
function render(){
  const R=document.getElementById('results');
  const recs=applyFilters();
  const inbound=recs.filter(r=>isInbound(r));
  const outbound=recs.filter(r=>!isInbound(r));
  const total=recs.length;
  const accepted=recs.filter(r=>r.action==='ACCEPT').length;
  const rejected=recs.filter(r=>r.action==='REJECT').length;
  const starts=recs.map(r=>r._start).filter(t=>t>0);
  const ends=recs.map(r=>r._end).filter(t=>t>0);
  const minT=Math.min(...starts),maxT=Math.max(...ends);
  const timeRange=minT&&maxT?`${new Date(minT*1000).toISOString().slice(0,19)}Z → ${new Date(maxT*1000).toISOString().slice(0,19)}Z`:'Unknown';

  const enis=[...new Set(recs.map(r=>r['interface-id']).filter(Boolean).filter(v=>v!=='-'))];
  const vpcs=[...new Set(recs.map(r=>r['vpc-id']).filter(Boolean).filter(v=>v!=='-'))];
  const accounts=[...new Set(recs.map(r=>r['account-id']).filter(Boolean).filter(v=>v!=='-'))];
  const eniList=[...new Set(recs.map(r=>r['interface-id']).filter(v=>v&&v!=='-'))];
  const eniOpts=eniList.map(e=>`<option value="${e}">${e}</option>`).join('');

  let html=`
  <nav class="section-nav" aria-label="Dashboard sections">
    <a href="#sec-security">🛡️ Security</a>
    <a href="#sec-outbound">⬆ Outbound</a>
    <a href="#sec-activity">📊 Activity</a>
  </nav>
  <div class="grid">
    <div class="s in"><div class="n">${total.toLocaleString()}</div><div class="l">Total Flows</div></div>
    <div class="s in"><div class="n">⬇ ${inbound.length.toLocaleString()}</div><div class="l">Inbound</div></div>
    <div class="s in"><div class="n">⬆ ${outbound.length.toLocaleString()}</div><div class="l">Outbound</div></div>
    <div class="s ok"><div class="n">${accepted.toLocaleString()}</div><div class="l">Allowed</div></div>
    <div class="s cr"><div class="n">${rejected.toLocaleString()}</div><div class="l">Blocked</div></div>
    <div class="s in"><div class="n">${formatBytes(recs.reduce((s,r)=>s+r._bytes,0))}</div><div class="l">Traffic</div></div>
  </div>
  <div class="card" style="border-left-color:var(--accent)">
    ${accounts.length?'<b>Account:</b> '+accounts.join(', ')+' | ':''}${vpcs.length?'<b>VPC:</b> '+vpcs.join(', ')+' | ':''}${enis.length?'<b>ENIs:</b> '+enis.join(', ')+' | ':''}Period: ${timeRange}
  </div>
  <div class="filters" id="filterBar">
    <label>Action:</label><select id="fAction"><option value="all">All</option><option value="ACCEPT">Accept</option><option value="REJECT">Reject</option></select>
    <label>Protocol:</label><select id="fProto"><option value="all">All</option><option value="6">TCP</option><option value="17">UDP</option><option value="1">ICMP</option></select>
    <label>ENI:</label><select id="fEni"><option value="all">All ENIs</option>${eniOpts}</select>
    <label>IP:</label><input id="fSearch" placeholder="e.g. 10.0.1.">
    <label>Port:</label><input id="fPort" placeholder="e.g. 3306" style="width:80px">
    <button onclick="applyAndRender()">Apply</button>
    <button onclick="resetFilters()" style="background:var(--muted)">Reset</button>
    <button id="resolveAllBtn" onclick="resolveAllGeo()" style="background:var(--warn)" title="Resolve country and org for top IPs using free GeoIP APIs">🌍 Resolve GeoIP</button>
  </div>`;

  const activeFilters=[];
  if(currentFilter.action!=='all')activeFilters.push('Action: '+currentFilter.action);
  if(currentFilter.protocol!=='all')activeFilters.push('Protocol: '+(PROTOS[currentFilter.protocol]||currentFilter.protocol));
  if(currentFilter.eni!=='all')activeFilters.push('ENI: '+currentFilter.eni);
  if(currentFilter.search)activeFilters.push('IP: '+currentFilter.search);
  if(currentFilter.port)activeFilters.push(`Port: ${currentFilter.port}/${PORTS[currentFilter.port]||''}`);
  if(activeFilters.length){
    html+=`<div class="active-filter-banner">🔍 Filtered by: ${activeFilters.map(f=>`<span class="filter-tag">${f}</span>`).join(' ')} <a href="#" onclick="resetFilters();return false" class="clear-filters">✕ Clear all</a></div>`;
  }

  // === SECTION 1: SECURITY POSTURE ===
  html+=`<div id="sec-security">`;
  html+=`<h2 style="color:var(--danger);font-size:1.3em;border-bottom:3px solid var(--danger)">🛡️ Security Posture</h2>`;
  html+=topSourceIPs(inbound);
  html+=topPorts(inbound,'dstport','Targeted Ports');
  html+=`</div>`;

  // === SECTION 2: OUTBOUND ===
  html+=`<div id="sec-outbound">`;
  html+=`<h2 style="color:var(--warn);font-size:1.3em;border-bottom:3px solid var(--warn)">⬆ Outbound Traffic</h2>`;
  html+=topDestIPs(outbound);
  html+=`</div>`;

  // === SECTION 3: ACTIVITY ===
  html+=`<div id="sec-activity">`;
  html+=`<h2 style="font-size:1.3em;border-bottom:3px solid var(--muted)">📊 Activity</h2>`;
  html+=timeline(recs);
  html+=`</div>`;

  R.innerHTML=html;
  R.style.display='block';
  document.getElementById('loading').classList.remove('show');
  document.getElementById('fAction').value=currentFilter.action;
  document.getElementById('fProto').value=currentFilter.protocol;
  document.getElementById('fEni').value=currentFilter.eni;
  document.getElementById('fSearch').value=currentFilter.search;
  document.getElementById('fPort').value=currentFilter.port;
  makeSortable();
}

// === ENI BREAKDOWN ===
// === TOP INBOUND SOURCE IPs ===
function topSourceIPs(recs){
  // Detect ENI own IPs: on egress, srcaddr is the ENI's IP
  const eniOwnIPs=new Set();
  allRecords.forEach(r=>{
    if(r['flow-direction']==='egress')eniOwnIPs.add(r.srcaddr);
    else if(r['flow-direction']==='ingress')eniOwnIPs.add(r.dstaddr);
  });
  const map={};
  recs.forEach(r=>{
    const ip=r.srcaddr;
    if(eniOwnIPs.has(ip))return; // skip ENI's own IPs — internal VPC traffic, not threats
    if(!map[ip])map[ip]={bytes:0,flows:0,accepted:0,rejected:0,ports:new Set(),hrPorts:new Set(),synOnly:0,priv:isPrivate(ip)};
    const d=map[ip];
    d.flows++;d.bytes+=r._bytes;
    r.action==='ACCEPT'?d.accepted++:d.rejected++;
    d.ports.add(r._dstport);
    if(HIGH_RISK_PORTS[r._dstport])d.hrPorts.add(r._dstport);
    if(r._tcpflags===2)d.synOnly++;
  });
  // Separate threats from noise
  const allEntries=Object.entries(map);
  const threats=allEntries.filter(([,d])=>d.hrPorts.size>0||d.rejected>0||d.synOnly>0).sort((a,b)=>b[1].flows-a[1].flows);
  const normal=allEntries.filter(([,d])=>d.hrPorts.size===0&&d.rejected===0&&d.synOnly===0).sort((a,b)=>b[1].flows-a[1].flows);

  let html='';
  if(threats.length){
    html+=`<h3>🎯 Inbound Threats — ${threats.length} IPs (<a href="https://docs.aws.amazon.com/config/latest/developerguide/restricted-common-ports.html">AWS Config Restricted Ports</a>)</h3>
    <p class="sub">${eniOwnIPs.size?'ENI own IPs excluded ('+[...eniOwnIPs].join(', ')+'). ':''}IPs that hit restricted ports, were blocked, or performed SYN scans.</p>
    <div class="tw"><table><thead><tr><th>Source IP</th><th>Country</th><th>Org</th><th>Ports Targeted</th><th>SYN %</th><th>Verdict</th><th>Flows</th><th>Bytes</th></tr></thead><tbody>`;
    threats.forEach(([ip,d])=>{
      const sp=d.flows?Math.round(d.synOnly/d.flows*100):0;
      const rList=[...d.hrPorts].map(p=>`<a href="#" onclick="filterByPort(${p});return false" class="port-chip">${p}/${HIGH_RISK_PORTS[p]||''}</a>`).join(' ');
      // Port scan detection: many unique ports + SYN = scanning
      let portsCell;
      if(d.hrPorts.size) portsCell=rList;
      else if(d.ports.size>10) portsCell=`<span class="t wa">Scanning ${d.ports.size} ports</span>`;
      else portsCell='—';
      let verdict;
      if(d.hrPorts.size&&d.accepted>0&&d.rejected===0){
        verdict=`<span class="t cr">⛔ ${d.accepted.toLocaleString()} allowed, none blocked</span>`;
      }else if(d.hrPorts.size&&d.accepted>0){
        verdict=`<span class="t cr">⚠️ ${d.accepted.toLocaleString()} allowed</span> / ${d.rejected.toLocaleString()} blocked`;
      }else if(d.accepted>0&&d.rejected===0&&(d.synOnly>0||d.ports.size>10)){
        verdict=`<span class="t cr">⛔ ${d.accepted.toLocaleString()} allowed, none blocked</span>`;
      }else if(d.rejected>0&&d.accepted===0){
        verdict=`<span class="t ok">✅ All ${d.rejected.toLocaleString()} blocked</span>`;
      }else if(d.rejected>0&&d.accepted>0){
        verdict=`<span class="t wa">⚠️ ${d.accepted.toLocaleString()} allowed</span> / ${d.rejected.toLocaleString()} blocked`;
      }else{
        verdict=`${d.accepted.toLocaleString()} allowed`;
      }
      html+=`<tr><td><b>${ip}</b></td><td>${ipGeoCell(ip)}</td><td>${ipOrgCell(ip)}</td>
      <td>${portsCell}</td>
      <td>${sp?`<span class="t ${sp>50?'cr':'wa'}">${sp}%</span>`:'—'}</td>
      <td>${verdict}</td>
      <td>${d.flows.toLocaleString()}</td><td>${formatBytes(d.bytes)}</td></tr>`;
    });
    html+='</tbody></table></div>';
  }
  if(normal.length){
    const shown=normal.slice(0,10);
    html+=`<h3>ℹ️ Other Inbound Sources — ${normal.length} IPs, no threat signals</h3>
    <p class="sub">Normal allowed traffic — no restricted ports, no blocks, no SYN scans.</p>
    <div class="tw"><table><thead><tr><th>Source IP</th><th>Country</th><th>Org</th><th>Flows</th><th>Bytes</th></tr></thead><tbody>`;
    shown.forEach(([ip,d])=>{
      html+=`<tr><td>${ip}</td><td>${ipGeoCell(ip)}</td><td>${ipOrgCell(ip)}</td>
      <td>${d.flows.toLocaleString()}</td><td>${formatBytes(d.bytes)}</td></tr>`;
    });
    html+='</tbody></table></div>';
  }
  return html;
}

// === TOP OUTBOUND DESTINATION IPs ===
function topDestIPs(recs){
  const eniIPs=new Set();
  allRecords.forEach(r=>{
    const eni=r['interface-id'];
    if(!eni||eni==='-')return;
    const dir=r['flow-direction'];
    if(dir==='egress')eniIPs.add(r.srcaddr);
    else if(dir==='ingress')eniIPs.add(r.dstaddr);
  });
  if(!eniIPs.size){
    const perEni={};
    allRecords.forEach(r=>{
      const eni=r['interface-id']||'?';
      if(!perEni[eni])perEni[eni]={src:new Set(),dst:new Set()};
      if(isPrivate(r.srcaddr))perEni[eni].src.add(r.srcaddr);
      if(isPrivate(r.dstaddr))perEni[eni].dst.add(r.dstaddr);
    });
    Object.values(perEni).forEach(e=>e.src.forEach(ip=>{if(e.dst.has(ip))eniIPs.add(ip);}));
  }
  const map={};
  recs.forEach(r=>{
    const ip=r.dstaddr;
    if(eniIPs.has(ip))return;
    if(!map[ip])map[ip]={bytes:0,flows:0,accepted:0,rejected:0,ports:new Set(),priv:isPrivate(ip)};
    const d=map[ip];
    d.flows++;d.bytes+=r._bytes;
    r.action==='ACCEPT'?d.accepted++:d.rejected++;
    d.ports.add(r._dstport);
  });
  const sorted=Object.entries(map).sort((a,b)=>b[1].bytes-a[1].bytes).slice(0,20);
  if(!sorted.length)return'';
  let html=`<h3>🎯 Top 20 Outbound Destinations by Volume — of ${Object.keys(map).length}</h3>
  <p class="sub">Sorted by bytes. ${eniIPs.size?'ENI own IPs excluded ('+[...eniIPs].join(', ')+').':''} Look for unexpected destinations or high data transfer.</p>
  <div class="tw"><table><thead><tr><th>Destination IP</th><th>Country</th><th>Org</th><th>Bytes</th><th>Flows</th><th>Status</th></tr></thead><tbody>`;
  sorted.forEach(([ip,d])=>{
    let status;
    if(d.rejected>0&&d.accepted===0){
      status=`<span class="t wa">All ${d.rejected.toLocaleString()} blocked</span>`;
    }else if(d.rejected>0){
      status=`<span class="t wa">${d.rejected.toLocaleString()} blocked</span> / ${d.accepted.toLocaleString()} sent`;
    }else{
      status=`<span class="t ok">${d.accepted.toLocaleString()} sent</span>`;
    }
    html+=`<tr><td><b>${ip}</b> ${d.priv?'<span class="t in">VPC</span>':''}</td><td>${ipGeoCell(ip)}</td><td>${ipOrgCell(ip)}</td>
    <td>${formatBytes(d.bytes)}</td><td>${d.flows.toLocaleString()}</td>
    <td>${status}</td></tr>`;
  });
  return html+'</tbody></table></div>';
}

// === GEO TABLE ===
// === TOP PORTS ===
function topPorts(recs,portField,title){
  const map={};
  recs.forEach(r=>{const p=parseInt(r[portField])||0;if(!p)return;if(!map[p])map[p]={accept:0,reject:0};r.action==='ACCEPT'?map[p].accept++:map[p].reject++;});
  const sorted=Object.entries(map).sort((a,b)=>(b[1].accept+b[1].reject)-(a[1].accept+a[1].reject));
  const top=sorted.slice(0,20);
  if(!top.length)return'';
  let html=`<h3>🔌 ${title} — Top 20 of ${sorted.length}</h3><div class="tw"><table><thead><tr><th>Port</th><th>Service</th><th>Flows</th><th>Blocked</th><th>Allowed</th></tr></thead><tbody>`;
  top.forEach(([port,d])=>{
    const t=d.accept+d.reject;
    const isRestricted=!!HIGH_RISK_PORTS[port];
    const allowedCls=isRestricted&&d.accept>0?'cr':d.accept>0?'in':'ok';
    html+=`<tr><td><a href="#" onclick="filterByPort(${port});return false" class="port-chip-table">${port}</a></td><td>${PORTS[port]||'—'} ${isRestricted?'<span class="t cr" style="font-size:.65em">restricted</span>':''}</td><td>${t.toLocaleString()}</td><td>${d.reject?d.reject.toLocaleString():'—'}</td><td>${d.accept?`<span class="t ${allowedCls}">${d.accept.toLocaleString()}</span>`:'—'}</td></tr>`;
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
    <td><div class="bar"><div class="fill" style="width:${ap}%;background:var(--success)"></div><div class="fill" style="width:${rp}%;background:var(--danger)"></div></div></td></tr>`;
  });
  return html+'</tbody></table></div>';
}
