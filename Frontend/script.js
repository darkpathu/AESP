/* AEPS light-mode frontend script
   - connects to WS_URL
   - updates: logs table, alerts, 3 charts
   - minimal sizes so everything fits on 1080p without page scroll
*/

const WS_URL = "ws://127.0.0.1:8000/stream"; // <--- change if your backend lives elsewhere\

const API_BASE = "http://127.0.0.1:8000";
let firewallEnabled = false;
const MAX_ROWS = 180;                      // how many rows to keep in table
const devices = new Map(); // ip -> { mac, lastSeen }


// UI elements
let backendStatus;
let devicesTbody;
let eventsTbody;
let alertsList;
let timelineChart;
let protocolChart;
let talkersChart;
// Aggregation state
const timeline = new Map();    // minuteKey -> count
const protoCounts = {TCP:0, UDP:0, ICMP:0, OTHER:0};
const talkers = new Map();     // src -> count

// Charts (Chart.js)


// helpers
function toTime(ts){
  const t = Number(ts);
  if(!t) return "-";
  return new Date(t * 1000).toLocaleTimeString();
}

function addRow(evt){
  try{
    if (!eventsTbody) return;
    const tr = document.createElement('tr');
    const bytes = (Number(evt.orig_bytes||0) + Number(evt.resp_bytes||0));
    tr.innerHTML = `<td>${toTime(evt.ts)}</td>
                    <td>${evt.src}</td>
                    <td>${evt.dst}</td>
                    <td>${evt.service||'-'}</td>
                    <td>${(evt.proto||'-').toUpperCase()}</td>
                    <td>${bytes}</td>
                    <td>${Number(evt.duration || 0).toFixed(2)}</td>
                    <td><span class="badge ${(evt.severity||'Low').toLowerCase().startsWith('h')?'high':(evt.severity||'Low').toLowerCase().startsWith('m')?'med':'low'}">${evt.severity||'Low'}</span></td>
                    <td>${evt.attack_type||''}</td>`;
    eventsTbody.insertBefore(tr, eventsTbody.firstChild);
    // trim
    while(eventsTbody.children.length > MAX_ROWS) eventsTbody.removeChild(eventsTbody.lastChild);
    }
    catch(e){
    console.error("Row failed:", e, evt);
    }
}


function updateDevices(evt){
  if (!devicesTbody) return;

  const ip = evt.src;
  if (!ip || ip === '-') return;

  const mac = evt.mac || 'Unknown';
  const now = Math.floor(Date.now() / 1000);

  devices.set(ip, { mac, lastSeen: now });

  devicesTbody.innerHTML = '';
  devices.forEach((v, k) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${k}</td>
      <td>${v.mac}</td>
      <td><span class="badge low">Active</span></td>
      <td>${toTime(v.lastSeen)}</td>
    `;
    devicesTbody.appendChild(tr);
  });
}


function pushAlert(evt){
  const ALERT_TTL = 60; // seconds
  const now = Math.floor(Date.now() / 1000);
  if (evt.ts && (now - evt.ts) > ALERT_TTL) return;
  if (!alertsList) return;
  if(!evt.severity) evt.severity='Low';
  if(evt.severity === 'Low') return; // only show med/high as alerts
  const card = document.createElement('div');
  card.className = 'alert-item';
  const severityClass = evt.severity === 'High' ? 'high' : 'med';
  card.innerHTML = `<div class="alert-left">
                      <div class="alert-title">
                        ${evt.attack_type || 'Suspicious'}
                        <span class="muted small">(${toTime(evt.ts)})</span>
                      </div>
                      <div class="alert-desc">${evt.src} → ${evt.dst} • ${evt.service || evt.proto}</div>
                    </div>
                    <div class="badge ${severityClass}">${evt.severity}</div>`;
  alertsList.prepend(card);
  // keep fixed number
  while(alertsList.children.length > 12) alertsList.removeChild(alertsList.lastChild);
}

function updateAgg(evt){
  // timeline: minute key
  const ts = Number(evt.ts) || Math.floor(Date.now() / 1000);
  const d = new Date(ts * 1000);
  d.setSeconds(0,0);
  const key = d.toLocaleTimeString();
  timeline.set(key, (timeline.get(key) || 0) + 1);

  // proto counts
  const p = (evt.proto || '').toUpperCase();
  if(p.includes('TCP')) protoCounts.TCP++;
  else if(p.includes('UDP')) protoCounts.UDP++;
  else if(p.includes('ICMP')) protoCounts.ICMP++;
  else protoCounts.OTHER++;

  // talkers
  talkers.set(evt.src, (talkers.get(evt.src) || 0) + 1);
}

function renderCharts(){
  // timeline: last 20 minutes slots
  const keys = Array.from(timeline.keys()).slice(-20);
  timelineChart.data.labels = keys;
  timelineChart.data.datasets[0].data = keys.map(k => timeline.get(k));
  timelineChart.update();

  // protocol pie
  protocolChart.data.datasets[0].data = [protoCounts.TCP, protoCounts.UDP, protoCounts.ICMP, protoCounts.OTHER];
  protocolChart.update();

  // top talkers
  const sorted = Array.from(talkers.entries()).sort((a,b)=>b[1]-a[1]).slice(0,8);
  talkersChart.data.labels = sorted.map(s=>s[0]);
  talkersChart.data.datasets[0].data = sorted.map(s=>s[1]);
  talkersChart.update();
}

async function toggleFirewall(){

  const url = firewallEnabled
    ? `${API_BASE}/firewall/disable`
    : `${API_BASE}/firewall/enable`;

  try{
      const res = await fetch(url,{method:"POST"});
      const data = await res.json();

      firewallEnabled = !firewallEnabled;

      const btn = document.getElementById("fwToggleBtn");

      if(firewallEnabled){
          btn.textContent="Firewall ON";
          btn.classList.remove("off");
          btn.classList.add("on");
      }else{
          btn.textContent="Firewall OFF";
          btn.classList.remove("on");
          btn.classList.add("off");
      }

  }catch(e){
      console.error(e);
  }
}
// WebSocket connection logic (with auto-reconnect)
let ws;
function connect(){
  backendStatus = document.getElementById('backendStatus');
  eventsTbody = document.getElementById('eventsTbody');
  alertsList = document.getElementById('alertsList');
  devicesTbody = document.getElementById('devicesTbody');

  // ---- SAFE chart init ----
  if (!timelineChart) {
    const tlEl = document.getElementById('timelineChart');
    const protoEl = document.getElementById('protocolChart');
    const talkEl = document.getElementById('talkersChart');

    if (tlEl && protoEl && talkEl) {
      timelineChart = new Chart(tlEl.getContext('2d'), {
        type: 'line',
        data: { labels: [], datasets: [{ label:'events/min', data:[], fill:true, tension:0.2 }] },
        options:{ plugins:{ legend:{display:false} }, scales:{ y:{beginAtZero:true} }, animation:false }
      });

      protocolChart = new Chart(protoEl.getContext('2d'), {
        type: 'pie',
        data: { labels:['TCP','UDP','ICMP','OTHER'], datasets:[{ data:[0,0,0,0] }] },
        options:{ plugins:{ legend:{ position:'bottom' } }, animation:false }
      });

      talkersChart = new Chart(talkEl.getContext('2d'), {
        type:'bar',
        data:{ labels:[], datasets:[{ label:'events', data:[], borderRadius:6 }] },
        options:{ plugins:{ legend:{display:false} }, scales:{ y:{beginAtZero:true} }, animation:false }
      });
    }
  }

  if (!backendStatus) return;


  try {
    ws = new WebSocket(WS_URL);
  } catch(e){
    setTimeout(connect, 1500);
    return;
  }

  ws.onopen = () => {
    // mark connected
    backendStatus.innerHTML = 'Backend: <span class="dot connected"></span> connected';
  };

  ws.onclose = () => {
    backendStatus.innerHTML = 'Backend: <span class="dot disconnected"></span> disconnected';
    setTimeout(connect, 1500);
  };

  ws.onerror = (ev) => {
    backendStatus.innerHTML = 'Backend: <span class="dot disconnected"></span> error';
  };

  ws.onmessage = (m) => {
    try {
      const data = JSON.parse(m.data);
      if(data.error){
        console.warn('backend error:', data.error);
        return;
      }
      // Normalize event structure
      const evt = {
        ts: Number(data.ts) || Math.floor(Date.now()/1000),
        src: data.src || data.saddr || '-',
        dst: data.dst || data.daddr || '-',
        sport: data.sport || '',
        dport: data.dport || '',
        proto: data.proto || '-',
        service: data.service || '-',
        duration: Number(data.duration||0),
        orig_bytes: Number(data.orig_bytes||0),
        resp_bytes: Number(data.resp_bytes||0),
        severity: data.severity || (data.ml?.label === 'THREAT' ? 'Medium' : 'Low'),
        attack_type: data.attack_type || data.type || (data.ml?.label === 'THREAT' ? 'ML: Threat' : ''),
        mac: data.mac,
        mac_last_seen: data.mac_last_seen
      };

      addRow(evt);
      pushAlert(evt);
      updateAgg(evt);
      renderCharts();
      updateDevices(evt);

    } catch(e){
      console.error('ws parse', e, m.data);
    }
  };
}

window.addEventListener('load', () => {

  connect();

  const btn = document.getElementById("fwToggleBtn");

  if(btn){
    btn.addEventListener("click", toggleFirewall);
  }
});
