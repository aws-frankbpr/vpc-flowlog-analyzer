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
  <nav class="section-nav" aria-label="Dashboard sections">
    <a href="#sec-eni">🔌 ENIs</a>
    <a href="#sec-inbound">⬇ Inbound</a>
    <a href="#sec-outbound">⬆ Outbound</a>
    <a href="#sec-timeline">📊 Timeline</a>
  </nav>
  <div class="card" style="border-left-color:var(--accent)">
    <b>${allRecords.length.toLocaleString()}</b> records parsed | Showing: <b>${total.toLocaleString()}</b> (⬇ ${inbound.length.toLocaleString()} inbound, ⬆ ${outbound.length.toLocaleString()} outbound) | Period: ${timeRange}<br>
    ${accounts.length?'<b>Account:</b> '+accounts.join(', ')+' | ':''}${vpcs.length?'<b>VPC:</b> '+vpcs.join(', ')+' | ':''}${subnets.length?'<b>Subnets:</b> '+subnets.join(', ')+' | ':''}${enis.length?'<b>ENIs:</b> '+enis.join(', '):''}
    ${privateIPs.length?'<br><b>Internal IPs:</b> '+privateIPs.slice(0,5).join(', ')+(privateIPs.length>5?' (+'+(privateIPs.length-5)+' more)':''):''}
  </div>
  <div class="filters" id="filterBar">
    <label>Action:</label><select id="fAction"><option value="all">All</option><option value="ACCEPT">Accept</option><option value="REJECT">Reject</option></select>
    <label>Protocol:</label><select id="fProto"><option value="all">All</option><option value="6">TCP</option><option value="17">UDP</option><option value="1">ICMP</option></select>
    <label>ENI:</label><select id="fEni"><option value="all">All ENIs</option>${eniOpts}</select>
    <label>Search IP:</label><input id="fSearch" placeholder="e.g. 10.0.1.">
    <label>Port:</label><input id="fPort" placeholder="e.g. 3306" style="width:80px">
    <button onclick="applyAndRender()">Apply</button>
    <button onclick="resetFilters()" style="background:var(--muted)">Reset</button>
    <button id="resolveAllBtn" onclick="resolveAllGeo()" style="background:var(--warn)" title="Resolve country and org for top IPs using free GeoIP APIs">🌍 Resolve GeoIP</button>
  </div>`;

  // Active filter banner
  const activeFilters=[];
  if(currentFilter.action!=='all')activeFilters.push('Action: '+currentFilter.action);
  if(currentFilter.protocol!=='all')activeFilters.push('Protocol: '+(PROTOS[currentFilter.protocol]||currentFilter.protocol));
  if(currentFilter.eni!=='all')activeFilters.push('ENI: '+currentFilter.eni);
  if(currentFilter.search)activeFilters.push('IP: '+currentFilter.search);
  if(currentFilter.port)activeFilters.push(`Port: ${currentFilter.port}/${PORTS[currentFilter.port]||''}`);
  if(activeFilters.length){
    html+=`<div class="active-filter-banner">🔍 Filtered by: ${activeFilters.map(f=>`<span class="filter-tag">${f}</span>`).join(' ')} <a href="#" onclick="resetFilters();return false" class="clear-filters">✕ Clear all</a></div>`;
  }

  html+=`<div id="sec-eni">`;
  html+=eniTable(recs);
  html+=`</div>`;

  html+=`<div id="sec-inbound">`;
  html+=`<h2 style="color:var(--accent);font-size:1.3em;border-bottom:3px solid var(--accent)">⬇ Inbound Traffic (${inbound.length.toLocaleString()} flows, ${formatBytes(inbound.reduce((s,r)=>s+r._bytes,0))})</h2>`;
  html+=summaryGrid(inbound);
  html+=topSourceIPs(inbound);
  html+=topPorts(inbound,'dstport','Top Inbound Destination Ports');
  html+=geoTable(inbound,'srcaddr');
  html+=protocolBreakdown(inbound);
  html+=`</div>`;

  html+=`<div id="sec-outbound">`;
  html+=`<h2 style="color:var(--warn);font-size:1.3em;border-bottom:3px solid var(--warn)">⬆ Outbound Traffic (${outbound.length.toLocaleString()} flows, ${formatBytes(outbound.reduce((s,r)=>s+r._bytes,0))})</h2>`;
  html+=summaryGrid(outbound);
  html+=topDestIPs(outbound);
  html+=topPorts(outbound,'dstport','Top Outbound Destination Ports');
  html+=geoTable(outbound,'dstaddr');
  html+=protocolBreakdown(outbound);
  html+=`</div>`;

  html+=`<div id="sec-timeline">`;
  html+=`<h2 style="font-size:1.3em;border-bottom:3px solid var(--muted)">📊 Combined Timeline</h2>`;
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

// === SUMMARY GRID ===
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

// === TOP INBOUND SOURCE IPs ===
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
  <div class="tw"><table><thead><tr><th>Source IP</th><th>Country</th><th>Org</th><th>Restricted Ports Hit</th><th>SYN-only %</th><th>Rejected</th><th>Accepted</th><th>Flows</th><th>Bytes</th><th>Unique Ports</th></tr></thead><tbody>`;
  sorted.forEach(([ip,d])=>{
    const sp=d.flows?Math.round(d.synOnly/d.flows*100):0;
    const rList=[...d.hrPorts].map(p=>`<a href="#" onclick="filterByPort(${p});return false" class="port-chip">${p}/${HIGH_RISK_PORTS[p]||''}</a>`).join(' ');
    const rjPct=d.flows?Math.round(d.rejected/d.flows*100):0;
    html+=`<tr><td><b>${ip}</b></td><td>${ipGeoCell(ip)}</td><td>${ipOrgCell(ip)}</td>
    <td>${d.hrPorts.size?rList:'—'}</td>
    <td>${sp?`<span class="t ${sp>50?'cr':'wa'}">${sp}%</span>`:'—'}</td>
    <td>${d.rejected.toLocaleString()} <span class="t ${rjPct>70?'cr':rjPct>30?'wa':'ok'}">${rjPct}%</span></td>
    <td>${d.accepted.toLocaleString()}</td>
    <td>${d.flows.toLocaleString()}</td><td>${formatBytes(d.bytes)}</td>
    <td>${d.ports.size.toLocaleString()}</td></tr>`;
  });
  return html+'</tbody></table></div>';
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
  let html=`<h3>🎯 Top 20 Outbound Destination IPs — of ${Object.keys(map).length}</h3>
  <p class="sub">Traffic to this ENI's own IPs excluded (${[...eniIPs].join(', ')}). Private IPs may indicate cross-subnet or cross-VPC communication.</p>
  <div class="tw"><table><thead><tr><th>Destination IP</th><th>Country</th><th>Org</th><th>Rejected</th><th>Bytes</th><th>Flows</th><th>Accepted</th><th>Unique Ports</th></tr></thead><tbody>`;
  sorted.forEach(([ip,d])=>{
    const rjPct=d.flows?Math.round(d.rejected/d.flows*100):0;
    html+=`<tr><td><b>${ip}</b> ${d.priv?'<span class="t in">VPC</span>':''}</td><td>${ipGeoCell(ip)}</td><td>${ipOrgCell(ip)}</td>
    <td>${d.rejected.toLocaleString()} ${d.rejected?`<span class="t ${rjPct>70?'cr':rjPct>30?'wa':'ok'}">${rjPct}%</span>`:''}</td>
    <td>${formatBytes(d.bytes)}</td><td>${d.flows.toLocaleString()}</td><td>${d.accepted.toLocaleString()}</td>
    <td>${d.ports.size.toLocaleString()}</td></tr>`;
  });
  return html+'</tbody></table></div>';
}

// === GEO TABLE ===
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
  <div class="tw"><table><thead><tr><th>Country</th><th>Reject Rate</th><th>Rejected</th><th>Accepted</th><th>Unique IPs</th></tr></thead><tbody>`;
  top.forEach(d=>{
    const t=d.accept+d.reject;const rp=t?Math.round(d.reject/t*100):0;
    const cls=rp>70?'cr':rp>30?'wa':'ok';
    html+=`<tr><td>${flag(d.cc)} ${d.country}</td><td><span class="t ${cls}">${rp}%</span></td><td>${d.reject.toLocaleString()}</td><td>${d.accept.toLocaleString()}</td><td>${d.ips.size}</td></tr>`;
  });
  return html+'</tbody></table></div>';
}

// === TOP PORTS ===
function topPorts(recs,portField,title){
  const map={};
  recs.forEach(r=>{const p=parseInt(r[portField])||0;if(!p)return;if(!map[p])map[p]={accept:0,reject:0};r.action==='ACCEPT'?map[p].accept++:map[p].reject++;});
  const sorted=Object.entries(map).sort((a,b)=>(b[1].accept+b[1].reject)-(a[1].accept+a[1].reject));
  const top=sorted.slice(0,20);
  if(!top.length)return'';
  let html=`<h3>🔌 ${title} — Top 20 of ${sorted.length}</h3><div class="tw"><table><thead><tr><th>Port</th><th>Service</th><th>Reject %</th><th>Total</th><th>Rejected</th><th>Accepted</th></tr></thead><tbody>`;
  top.forEach(([port,d])=>{
    const t=d.accept+d.reject;const rp=t?Math.round(d.reject/t*100):0;const cls=rp>70?'cr':rp>30?'wa':'ok';
    html+=`<tr><td><a href="#" onclick="filterByPort(${port});return false" class="port-chip-table">${port}</a></td><td>${PORTS[port]||'—'}</td><td><span class="t ${cls}">${rp}%</span></td><td>${t.toLocaleString()}</td><td>${d.reject.toLocaleString()}</td><td>${d.accept.toLocaleString()}</td></tr>`;
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
    <td><div class="bar"><div class="fill" style="width:${ap}%;background:var(--success)"></div><div class="fill" style="width:${rp}%;background:var(--danger)"></div></div></td></tr>`;
  });
  return html+'</tbody></table></div>';
}
