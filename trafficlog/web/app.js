import {actions,fields,ipNumber,compileFilter,normalizeFilterValue,formatFilterValue,parseFilterInput} from "./filters.mjs";

const $ = (id) => document.getElementById(id);
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const icon = name => `<svg aria-hidden="true"><use href="#i-${name}"/></svg>`;
const services = {20:"FTP",21:"FTP",22:"SSH",25:"SMTP",53:"DNS",67:"DHCP",68:"DHCP",80:"HTTP",123:"NTP",161:"SNMP",179:"BGP",443:"HTTPS",445:"SMB",3389:"RDP",8000:"HTTP",8291:"WinBox"};
const state = {token:"",router:null,rules:[],knownRules:new Set(),selected:new Set(),events:[],sequence:0,session:null,view:"traffic",filters:[],search:"",sort:"received",descending:true,page:0,pageSize:100,paused:false,pausedEvents:null,detail:null,closed:false,lastRuleSignature:""};
let toastTimer, pollBusy = false, previewVersion = 0, previewPlan = null;
let suggestions=[], activeSuggestion=-1, editingFilter=null;

function toast(message) {
  $("toast").textContent = message;
  $("toast").classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => $("toast").classList.add("hidden"), 4500);
}

async function api(path, body = {}) {
  const response = await fetch(path, {method:"POST", headers:{"Content-Type":"application/json","X-Local-Token":state.token}, body:JSON.stringify(body)});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Request failed");
  return result;
}

function isActive() { return ["starting","running","stopping"].includes(state.session?.phase); }
function openDialog(id) { if (!$(id).open) $(id).showModal(); }
function closeDialog(id) { $(id).close(); }
function errorBox(id, message) { $(id).textContent = message; $(id).classList.toggle("hidden", !message); }
function setPaused(paused) {
  state.paused=paused; state.pausedEvents=paused?[...state.events]:null;
  $("pause-button").classList.toggle("paused",paused);
  $("pause-button").setAttribute("aria-pressed",String(paused));
  $("pause-button").querySelector("span").textContent=paused?"Resume":"Pause";
}

function showView(view) {
  state.view = view;
  for (const name of ["traffic","rules","session"]) $("view-" + name).classList.toggle("hidden", name !== view);
  document.querySelectorAll("[data-view]").forEach(b => b.classList.toggle("active", b.dataset.view === view));
  $("page-title").textContent = {traffic:"Traffic Log",rules:"Rules",session:"Router changes"}[view];
  if (view === "rules") renderRules();
  if (view === "session") renderSession();
}

function consume(data) {
  const key = (data.router?.address || "");
  const oldKey = (state.router?.address || "");
  if (key !== oldKey) {
    state.selected.clear(); state.knownRules.clear(); state.events = []; state.detail = null;
    $("detail-drawer").classList.add("hidden");
    if(oldKey){state.filters=[];state.search="";$("search").value="";editingFilter=null;closeSuggestions();}
    state.page=0;setPaused(false);
  }
  state.router = data.router; state.session = data.session;
  state.rules = data.rules || [];
  for (const rule of state.rules) {
    if (!state.knownRules.has(rule.id) && rule.selected) state.selected.add(rule.id);
    state.knownRules.add(rule.id);
  }
  const ids = new Set(state.rules.map(r => r.id));
  state.selected.forEach(id => { if (!ids.has(id)) state.selected.delete(id); });
  if (data.events?.length) {
    const seen = new Set(state.events.map(e => e.sequence));
    state.events.push(...data.events.filter(e => !seen.has(e.sequence)));
    if (state.events.length > 10000) state.events.splice(0, state.events.length - 10000);
  }
  state.sequence = data.sequence;
  renderStatus();
  if (!state.paused) renderTraffic();
  else $("pause-button").querySelector("span").textContent = `Resume (${Math.max(0,state.events.length - state.pausedEvents.length)} new)`;
  const signature = JSON.stringify(state.rules);
  if (state.view === "rules" && signature !== state.lastRuleSignature) renderRules();
  state.lastRuleSignature = signature;
  if (state.view === "session") renderSession();
}

async function poll() {
  if (pollBusy || state.closed) return;
  pollBusy = true;
  try {
    const response = await fetch(`/api/state?since=${state.sequence}`, {cache:"no-store"});
    if (!response.ok) throw new Error("Local connection failed");
    consume(await response.json());
    $("sidebar-status").textContent = state.router ? state.router.address : "";
  } catch (err) {
    $("sidebar-status").textContent = "Application unavailable";
  } finally { pollBusy = false; }
}

function renderStatus() {
  $("router-label").textContent = state.router ? state.router.name : "Connect router";
  const session = state.session;
  const live = session?.phase === "running";
  const busy = ["starting","stopping"].includes(session?.phase);
  const remaining = session ? Math.max(0, Math.ceil((session.expires - Date.now()/1000)/60)) : 0;
  const status = $("capture-status");
  status.classList.toggle("live", live);
  status.textContent = live ? `Live · ${remaining} min` : busy ? "Please wait…" : "Stopped";
  const button = $("capture-button");
  button.classList.toggle("primary", !isActive()); button.classList.toggle("stop", isActive());
  button.innerHTML = isActive() ? icon("stop") + "Stop" : icon("play") + "Start capture";
  button.disabled = session?.phase === "stopping";
  $("refresh-rules").disabled = isActive() || !state.router;
  $("find-sessions").disabled = isActive() || !state.router;
  for(const id of ["select-default","select-block","select-none"]) $(id).disabled=isActive();
  const messages = [];
  if (session?.phase === "starting" || session?.phase === "stopping") messages.push(session.message);
  if (session?.error) messages.push(session.error);
  if (session?.cleanup_errors?.length) messages.push("Cleanup incomplete. Retry in Router changes; the expiry task is still in place.");
  if (session?.buffer_pressure) messages.push("High log rate: events may be lost. Narrow capture to a source IP.");
  if (session?.parse_errors) messages.push(`${session.parse_errors} messages could not be parsed.`);
  if (session?.skipped?.length) messages.push(`${session.skipped.length} rules skipped. See Router changes.`);
  $("status-message").textContent = messages.join(" ");
  $("status-message").classList.toggle("hidden", !messages.length);
  $("status-message").classList.toggle("error", !!session?.error || !!session?.cleanup_errors?.length);
  $("export-button").disabled = !state.events.length;
  $("clear-button").disabled = !state.events.length;
  $("pause-button").disabled = !state.events.length;
}

function filteredEvents() {
  const events=state.paused?state.pausedEvents:state.events;
  const predicates=state.filters.map(f=>compileFilter(f.field,f.value));
  if(state.search.trim())predicates.push(compileFilter("text",state.search));
  const result=events.filter(e=>predicates.every(test=>test(e)));
  result.sort((a,b) => {
    let av=a[state.sort] ?? "",bv=b[state.sort] ?? "", comparison;
    if (["source","destination"].includes(state.sort)) {try {av=ipNumber(av);bv=ipNumber(bv);} catch {}}
    comparison = typeof av==="number" && typeof bv==="number" ? av-bv : String(av).localeCompare(String(bv),"en",{numeric:true});
    return (state.descending ? -1 : 1) * comparison;
  });
  return result;
}

function actionBadge(action) {
  return `<span class="action-badge ${esc(action)}">${icon(action==="accept" ? "check" : "x")}${esc(actions[action] || action)}</span>`;
}

function displayTime(event) {
  const date = new Date(event.received);
  return isNaN(date) ? esc(event.time) : date.toLocaleTimeString("en-GB", {hour:"2-digit",minute:"2-digit",second:"2-digit"});
}

function renderTraffic() {
  const all = state.paused ? state.pausedEvents : state.events;
  const allowed = all.filter(e => e.action==="accept").length;
  $("metric-total").textContent = all.length.toLocaleString("en-GB");
  $("metric-allow").textContent = allowed.toLocaleString("en-GB");
  $("metric-deny").textContent = all.filter(e => ["drop","reject"].includes(e.action)).length.toLocaleString("en-GB");
  $("metric-sources").textContent = new Set(all.map(e => e.source)).size;
  const rows = filteredEvents();
  state.page = Math.min(state.page, Math.max(0, Math.ceil(rows.length/state.pageSize)-1));
  const start = state.page*state.pageSize, page = rows.slice(start,start+state.pageSize);
  $("traffic-body").innerHTML = page.map(e => `<tr data-event="${e.sequence}" class="${state.detail?.sequence===e.sequence ? "selected" : ""}" tabindex="0" aria-label="Event ${esc(e.source)} to ${esc(e.destination)}">
    <td class="time" title="Received: ${esc(e.received)}">${displayTime(e)}<span class="subline">${esc(new Date(e.received).toLocaleDateString("en-GB", {day:"2-digit",month:"2-digit"}))}</span></td>
    <td class="ip"><button class="cell-link" data-filter-field="source" data-value="${esc(e.source)}">${esc(e.source)}</button><span class="subline">${e.source_port ? ":"+e.source_port : "—"}</span></td>
    <td class="ip"><button class="cell-link" data-filter-field="destination" data-value="${esc(e.destination)}">${esc(e.destination)}</button></td>
    <td class="port"><button class="cell-link" data-filter-field="destination_port" data-value="${esc(e.destination_port ?? "")}">${e.destination_port ?? "—"}</button><span class="service-name">${services[e.destination_port] || ""}</span></td>
    <td><span class="protocol-tag">${esc(e.protocol)}</span></td><td>${actionBadge(e.action)}</td>
    <td class="rule-cell" title="${esc(e.rule_name)}">${esc(e.rule_name)}<span class="rule-index">#${e.rule_position}</span></td>
    <td class="interface">${esc(e.input)}</td><td class="interface">${esc(e.output)}</td><td class="interface">${esc(e.chain)}</td><td class="interface">${e.length ?? "—"} B</td></tr>`).join("");
  $("empty-state").classList.toggle("hidden", !!rows.length);
  if (!rows.length) {
    const empty = $("empty-state");
    empty.querySelector("h2").textContent = all.length ? "No matches." : "No entries.";
    $("empty-connect").innerHTML = all.length ? "Reset filters" : state.router ? icon("play")+"Start capture" : "Connect router";
    $("empty-connect").disabled = !!state.router && isActive() && !all.length;
  }
  const sortLabel = state.sort==="received" ? (state.descending?"newest first":"oldest first") : "sorted by column";
  $("result-label").textContent = `${rows.length.toLocaleString("en-GB")} matches · ${state.paused ? "paused" : sortLabel}`;
  $("page-label").textContent = `${rows.length ? start+1 : 0}–${Math.min(start+state.pageSize,rows.length)} of ${rows.length.toLocaleString("en-GB")}`;
  $("previous-page").disabled = state.page===0;
  $("next-page").disabled = start+state.pageSize >= rows.length;
  $("filter-chips").classList.toggle("hidden", !state.filters.length);
  $("filter-chips").innerHTML=state.filters.map(renderFilterChip).join("");
  document.querySelectorAll("th[data-sort]").forEach(th => {
    th.classList.toggle("sorted", th.dataset.sort===state.sort);
    th.querySelector("span").textContent = th.dataset.sort===state.sort ? (state.descending ? "↓" : "↑") : "↕";
  });
}

function addFilter(field,value,index=null) {
  value=normalizeFilterValue(field,value);compileFilter(field,value);
  const filter={field,value};
  if(index!==null)state.filters.splice(index,1);
  if(!state.filters.some(f=>f.field===field&&f.value===value))state.filters.push(filter);
  state.page=0;renderTraffic();
}

function resetFilters() {
  state.filters=[];state.page=0;cancelFilterInput();
}

function renderRules() {
  const terms = $("rule-search").value.toLocaleLowerCase().trim().split(/\s+/).filter(Boolean), chain = $("rule-chain").value;
  const rows = state.rules.filter(r => {
    const text=[r.id,`#${r.position}`,r.name,r.action,actions[r.action],r.chain,r.source,r.destination,r.ports,r.protocol,r.state,r.reason,r.search_text].join(" ").toLocaleLowerCase();
    return (!chain || r.chain===chain) && terms.every(term=>text.includes(term));
  });
  $("rules-body").innerHTML = rows.map(r => `<tr class="${r.eligible ? "" : "ineligible"}"><td><input type="checkbox" data-rule="${esc(r.id)}" aria-label="Rule ${esc(r.name)} select" ${state.selected.has(r.id)?"checked":""} ${!r.eligible || isActive()?"disabled":""}></td><td>${r.position}</td><td>${esc(r.name)}</td><td>${actionBadge(r.action)}</td><td>${esc(r.chain)}</td><td class="ip">${esc(r.source)}</td><td class="ip">${esc(r.destination)}${r.ports ? ":"+esc(r.ports) : ""}</td><td>${esc(r.reason || (r.state ? "State: "+r.state : ""))}</td></tr>`).join("");
  $("rules-empty").classList.toggle("hidden", !!rows.length);
  $("rules-empty").textContent = "No rules.";
  $("selection-count").textContent = `${state.selected.size} selected`;
}

function renderSession() {
  const s = state.session;
  const items = s ? [["Status",s.message],["Router",state.router?.name || "—"],["Session ID",s.id],["Start",new Date(s.started*1000).toLocaleString("en-GB")],["Time limit",new Date(s.expires*1000).toLocaleTimeString("en-GB")],["Temporary log rules",s.probes]] : [["Status","No capture"]];
  $("session-details").innerHTML = items.map(([k,v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("") + (s?.skipped || []).map(r => `<dt>Skipped</dt><dd>${esc(r.name)}<br><small>${esc(r.reason)}</small></dd>`).join("");
  $("session-change-details").classList.toggle("hidden", !s);
  setScript("session-commands",s?.commands || "");
  setScript("session-undo",s?.undo || "");
}

function openDetails(event) {
  state.detail = event;
  const detail = $("detail-content");
  const pairs = [["Rule", event.rule_name],["Rule number",`#${event.rule_position} · ${event.rule_id}`],["Protocol",event.protocol],["Connection state",event.state || "—"],["Ingress",event.input],["Egress",event.output],["Chain",event.chain],["Packet length",`${event.length ?? "—"} Bytes`],["Source MAC",event.source_mac || "—"],["Router",event.router],["Router time",event.time],["Received",new Date(event.received).toLocaleString("en-GB")]];
  detail.innerHTML = `${actionBadge(event.action)}<div class="endpoints"><div><div class="endpoint-label">SOURCE</div><div class="endpoint-value">${esc(event.source)}${event.source_port ? ":"+event.source_port : ""}</div><button class="detail-filter" data-filter-field="source" data-value="${esc(event.source)}">Filter by source</button></div><span>↓</span><div><div class="endpoint-label">DESTINATION</div><div class="endpoint-value">${esc(event.destination)}${event.destination_port != null ? ":"+event.destination_port : ""}</div><button class="detail-filter" data-filter-field="destination" data-value="${esc(event.destination)}">Filter by destination</button></div></div><dl>${pairs.map(([k,v])=>`<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl><details><summary>Raw message</summary><pre>${esc(event.raw)}</pre></details>`;
  $("detail-drawer").classList.remove("hidden");
}

function renderFilterChip(filter,index){
  return '<span class="filter-chip'+(editingFilter===index?' editing':'')+'"><button type="button" data-edit-filter="'+index+'">'+esc(fields[filter.field])+': <strong>'+esc(formatFilterValue(filter.field,filter.value))+'</strong></button><button type="button" data-remove-filter="'+index+'" aria-label="Remove '+esc(fields[filter.field])+' filter">'+icon("x")+'</button></span>';
}

function closeSuggestions(){
  $("filter-suggestions").classList.add("hidden");
  $("search").setAttribute("aria-expanded","false");
  $("search").removeAttribute("aria-activedescendant");
  activeSuggestion=-1;
}

function filterSuggestions(){
  const input=$("search").value,parsed=parseFilterInput(input);
  if(parsed){
    let values=parsed.field==="action"?Object.keys(actions):parsed.field==="protocol"?["TCP","UDP","ICMP","ICMPV6"]:[];
    values=[...new Set([...values,...state.events.map(e=>e[parsed.field]).filter(v=>v!==null&&v!==undefined&&v!=="").map(String)])];
    const term=parsed.value.toLowerCase();
    return values.filter(v=>v.toLowerCase().includes(term)||formatFilterValue(parsed.field,v).toLowerCase().includes(term))
      .slice(0,12).map(value=>({type:"value",field:parsed.field,value,label:formatFilterValue(parsed.field,value)}));
  }
  const term=input.trim().toLowerCase();
  const rows=Object.entries(fields).filter(([field,label])=>field!=="text"&&(!term||label.toLowerCase().includes(term)||field.includes(term)))
    .map(([field,label])=>({type:"field",field,label}));
  if(term)rows.push({type:"search",field:"text",value:input.trim(),label:'Search: '+input.trim()});
  return rows;
}

function renderSuggestions(){
  suggestions=filterSuggestions();
  activeSuggestion=-1;
  $("filter-suggestions").innerHTML=suggestions.map((item,index)=>'<button type="button" role="option" aria-selected="false" id="filter-option-'+index+'" data-suggestion="'+index+'">'+esc(item.label)+'</button>').join("");
  $("filter-suggestions").classList.toggle("hidden",!suggestions.length);
  $("search").setAttribute("aria-expanded",String(!!suggestions.length));
  $("search").removeAttribute("aria-activedescendant");
}

function chooseSuggestion(index){
  const item=suggestions[index];
  if(!item)return;
  if(item.type==="field"){
    $("search").value=fields[item.field]+": ";
    state.search="";
    errorBox("filter-error","");
    renderTraffic();renderSuggestions();$("search").focus();
  }else commitFilter(item.field,item.value);
}

function commitFilter(field,value){
  try{
    addFilter(field,value,editingFilter);
    editingFilter=null;state.search="";$("search").value="";
    errorBox("filter-error","");closeSuggestions();renderTraffic();$("search").focus();
  }catch(err){errorBox("filter-error",err.message);}
}

function commitFilterInput(){
  const input=$("search").value.trim();
  if(!input)return;
  const parsed=parseFilterInput(input);
  if(parsed)commitFilter(parsed.field,parsed.value);
  else commitFilter("text",input);
}

function cancelFilterInput(){
  editingFilter=null;state.search="";$("search").value="";
  errorBox("filter-error","");closeSuggestions();renderTraffic();
}

function moveSuggestion(direction){
  if($("filter-suggestions").classList.contains("hidden"))renderSuggestions();
  if(!suggestions.length)return;
  activeSuggestion=activeSuggestion<0?(direction>0?0:suggestions.length-1):(activeSuggestion+direction+suggestions.length)%suggestions.length;
  $("filter-suggestions").querySelectorAll("[role=option]").forEach((option,index)=>{
    option.setAttribute("aria-selected",String(index===activeSuggestion));
  });
  const option=$("filter-option-"+activeSuggestion);
  $("search").setAttribute("aria-activedescendant",option.id);
  option.scrollIntoView({block:"nearest"});
}
function exportCSV() {
  const rows=filteredEvents();
  if (!rows.length) return toast("No matching events to export.");
  const columns=["received","source","source_port","destination","destination_port","protocol","action","rule_name","chain","input","output","state","length","router","raw"];
  const cell=v=>{let text=String(v??"");if(/^[=+\-@\t\r]/.test(text))text="'"+text;return '"'+text.replace(/"/g,'""')+'"';};
  const csv="\ufeff"+[columns.join(";"),...rows.map(r=>columns.map(c=>cell(r[c])).join(";"))].join("\r\n");
  const url=URL.createObjectURL(new Blob([csv],{type:"text/csv;charset=utf-8"}));
  const a=document.createElement("a");a.href=url;a.download=`mikrotik-trafficlog-${new Date().toISOString().slice(0,19).replace(/:/g,"-")}.csv`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
  toast(`${rows.length} events exported.`);
}

function openCapture() {
  if (!state.router) return openConnection();
  if (!state.selected.size) {showView("rules");return toast("Select at least one eligible rule.");}
  $("capture-selection").textContent=`${state.selected.size} Rules`;
  errorBox("capture-error","");openDialog("capture-dialog");refreshPreview();
}

function setScript(id, text) {
  if($(id).value!==text) $(id).value=text;
  document.querySelectorAll(`[data-copy="${id}"]`).forEach(b=>b.disabled=!text);
}

async function copyScript(id) {
  const input=$(id);
  if(!input?.value)return;
  try {await navigator.clipboard.writeText(input.value);toast("Copied.");}
  catch {input.focus();input.select();toast("Press Ctrl+C to copy.");}
}

function captureOptions() {
  return {rules:[...state.selected],minutes:Number($("capture-minutes").value),new_only:$("capture-mode").value==="new",source_ip:$("capture-source").value.trim()};
}

async function refreshPreview() {
  const version=++previewVersion;
  previewPlan=null;$("capture-submit").disabled=true;
  setScript("capture-commands","");setScript("capture-undo","");
  $("capture-plan-summary").textContent="Loading commands…";
  errorBox("capture-error","");
  try {
    const payload=captureOptions();if(payload.source_ip)ipNumber(payload.source_ip);
    const plan=await api("/api/capture/preview",payload);
    if(version!==previewVersion)return;
    previewPlan=plan;
    setScript("capture-commands",plan.commands || "");setScript("capture-undo",plan.undo || "");
    $("capture-plan-summary").textContent=`${plan.planned} log rules + 1 logging action + 1 logging rule + 1 expiry task`;
    if(plan.skipped?.length)$("capture-plan-summary").textContent+=` · ${plan.skipped.length} skipped`;
    $("capture-submit").disabled=false;
  }catch(e){if(version===previewVersion){$("capture-plan-summary").textContent="";errorBox("capture-error",e.message);}}
}

function updateTLSOption() {
  $("tls-option").classList.toggle("hidden",!$("router-address").value.trim().toLowerCase().startsWith("https://"));
}

async function openConnection() {
  errorBox("connection-error","");openDialog("connection-dialog");
  $("router-address").value="";$("connect-submit").disabled=true;
  try {
    const response=await fetch("/api/defaults",{cache:"no-store"});
    if(!response.ok)throw new Error("Gateway lookup failed.");
    $("router-address").value=(await response.json()).address || "";
  }catch(e){errorBox("connection-error",e.message);}
  finally{$("connect-submit").disabled=false;updateTLSOption();}
}

document.querySelectorAll("[data-close]").forEach(b=>b.addEventListener("click",()=>closeDialog(b.dataset.close)));
document.querySelectorAll("[data-view]").forEach(b=>b.addEventListener("click",()=>showView(b.dataset.view)));
$("connection-button").onclick=openConnection;
$("router-address").oninput=updateTLSOption;
document.querySelectorAll("[data-copy]").forEach(b=>b.onclick=()=>copyScript(b.dataset.copy));
$("connection-dialog").addEventListener("close",()=>{$("router-password").value="";});
$("connection-form").onsubmit=async e=>{
  e.preventDefault();errorBox("connection-error","");
  const button=$("connect-submit");button.disabled=true;button.textContent="Connecting…";
  const payload={address:$("router-address").value,username:$("router-user").value,password:$("router-password").value,verify_tls:!$("self-signed").checked,allow_http:true};
  $("router-password").value="";
  try {
    const result=await api("/api/connect",payload);consume(result);
    try{localStorage.setItem("mikrotik-trafficlog-connection",JSON.stringify({username:payload.username}));}catch{}
    closeDialog("connection-dialog");showView("rules");
  }catch(err){errorBox("connection-error",err.message);}finally{button.disabled=false;button.textContent="Connect";payload.password="";}
};
$("capture-button").onclick=async()=>{if(isActive()){try{await api("/api/capture/stop");await poll();}catch(e){toast(e.message);}}else openCapture();};
$("capture-form").onsubmit=async e=>{
  e.preventDefault();errorBox("capture-error","");
  const source=$("capture-source").value.trim();
  try{
    if(source)ipNumber(source);
    if(!previewPlan)return;
    $("capture-submit").disabled=true;
    await api("/api/capture/start",{...captureOptions(),plan_id:previewPlan.plan_id});
    state.events=[];setPaused(false);closeDialog("capture-dialog");showView("traffic");await poll();
  }catch(err){errorBox("capture-error",err.message);}finally{$("capture-submit").disabled=false;}
};
for(const id of ["capture-mode","capture-minutes","capture-source"])$(id).onchange=refreshPreview;
$("edit-selection").onclick=()=>{closeDialog("capture-dialog");showView("rules");};
$("empty-connect").onclick=()=>state.events.length ? resetFilters() : state.router ? openCapture() : openConnection();
$("filter-form").onsubmit=e=>{e.preventDefault();commitFilterInput();};
$("search").onfocus=renderSuggestions;
$("search").onclick=renderSuggestions;
$("search").oninput=()=>{
  errorBox("filter-error","");
  state.search=parseFilterInput($("search").value)?"":$("search").value;
  state.page=0;renderTraffic();renderSuggestions();
};
$("search").onkeydown=e=>{
  if(e.key==="ArrowDown"||e.key==="ArrowUp"){e.preventDefault();moveSuggestion(e.key==="ArrowDown"?1:-1);}
  else if(e.key==="Enter"){e.preventDefault();if(activeSuggestion>=0)chooseSuggestion(activeSuggestion);else commitFilterInput();}
  else if(e.key==="Escape"){e.preventDefault();e.stopPropagation();cancelFilterInput();}
  else if(e.key==="Backspace"&&!$("search").value&&editingFilter===null&&state.filters.length){
    state.filters.pop();state.page=0;renderTraffic();
  }
};
$("filter-suggestions").onpointerdown=e=>e.preventDefault();
$("filter-suggestions").onclick=e=>{const option=e.target.closest("[data-suggestion]");if(option)chooseSuggestion(Number(option.dataset.suggestion));};
$("filter-chips").onclick=e=>{
  const remove=e.target.closest("[data-remove-filter]"),edit=e.target.closest("[data-edit-filter]");
  if(remove){
    const index=Number(remove.dataset.removeFilter);state.filters.splice(index,1);
    if(editingFilter===index)cancelFilterInput();else if(editingFilter!==null&&editingFilter>index)editingFilter--;
    state.page=0;renderTraffic();$("search").focus();
  }else if(edit){
    editingFilter=Number(edit.dataset.editFilter);const filter=state.filters[editingFilter];
    $("search").value=fields[filter.field]+": "+formatFilterValue(filter.field,filter.value);
    state.search="";errorBox("filter-error","");renderTraffic();$("search").focus();renderSuggestions();
  }
};
$("filter-bar").onclick=e=>{if(e.target===$("filter-bar")||e.target===$("filter-chips"))$("search").focus();};
document.addEventListener("pointerdown",e=>{if(!$("filter-form").contains(e.target))closeSuggestions();});
$("pause-button").onclick=()=>{
  setPaused(!state.paused);renderTraffic();
};
$("clear-button").onclick=async()=>{try{await api("/api/events/clear");state.events=[];if(state.paused)state.pausedEvents=[];state.page=0;renderTraffic();}catch(e){toast(e.message);}};
$("export-button").onclick=exportCSV;
$("page-size").onchange=e=>{state.pageSize=Number(e.target.value);state.page=0;renderTraffic();};
$("previous-page").onclick=()=>{state.page--;renderTraffic();};$("next-page").onclick=()=>{state.page++;renderTraffic();};
document.querySelectorAll("th[data-sort]").forEach(th=>th.onclick=()=>{if(state.sort===th.dataset.sort)state.descending=!state.descending;else{state.sort=th.dataset.sort;state.descending=false;}state.page=0;renderTraffic();});
function rowAction(e){
  const f=e.target.closest("[data-filter-field]");
  if(f){if(f.dataset.value){try{addFilter(f.dataset.filterField,f.dataset.value);}catch(err){toast(err.message);}}return;}
  const row=e.target.closest("[data-event]");if(row){const event=state.events.find(x=>x.sequence===Number(row.dataset.event));if(event)openDetails(event);}
}
$("traffic-body").onclick=rowAction;$("traffic-body").onkeydown=e=>{if(e.key==="Enter")rowAction(e);};
$("detail-content").onclick=rowAction;$("close-details").onclick=()=>{state.detail=null;$("detail-drawer").classList.add("hidden");};
$("rule-search").oninput=renderRules;$("rule-chain").onchange=renderRules;
$("rules-body").onchange=e=>{if(e.target.dataset.rule){e.target.checked?state.selected.add(e.target.dataset.rule):state.selected.delete(e.target.dataset.rule);$("selection-count").textContent=`${state.selected.size} selected`;}};
$("select-default").onclick=()=>{if(isActive())return;state.selected=new Set(state.rules.filter(r=>r.eligible).map(r=>r.id));renderRules();};
$("select-block").onclick=()=>{if(isActive())return;state.selected=new Set(state.rules.filter(r=>r.eligible&&["drop","reject"].includes(r.action)).map(r=>r.id));renderRules();};
$("select-none").onclick=()=>{if(isActive())return;state.selected.clear();renderRules();};
$("refresh-rules").onclick=async()=>{try{consume(await api("/api/rules/refresh"));renderRules();toast("Rules reloaded.");}catch(e){toast(e.message);}};
$("find-sessions").onclick=async()=>{
  const button=$("find-sessions");button.disabled=true;
  try{const result=await api("/api/sessions/find");$("orphan-results").innerHTML=result.sessions.length?`<p>${result.sessions.length} captures</p><button class="button stop" id="cleanup-sessions">Remove</button>`:"<p>No sessions.</p>";
    for(const item of result.cleanup || []){
      const box=document.createElement("div");box.className="orphan-session";
      box.innerHTML=`<div class="section-heading"><strong>${esc(item.id)}</strong><button data-copy="undo-${esc(item.id)}">Copy rollback</button></div><textarea class="script" id="undo-${esc(item.id)}" readonly rows="5"></textarea>`;
      $("orphan-results").append(box);$("undo-"+item.id).value=item.undo;box.querySelector("button").onclick=()=>copyScript("undo-"+item.id);
    }
    const cleanup=$("cleanup-sessions");if(cleanup)cleanup.onclick=async()=>{cleanup.disabled=true;try{await api("/api/sessions/cleanup",{sessions:result.sessions});$("orphan-results").textContent="Temporary rules removed.";toast("Cleanup complete.");await poll();}catch(e){toast(e.message);cleanup.disabled=false;}};
  }catch(e){toast(e.message);}finally{button.disabled=false;}
};
$("shutdown-button").onclick=async()=>{
  try{await api("/api/shutdown");state.closed=true;$("status-message").textContent="Shutting down…";$("status-message").classList.remove("hidden");}catch(e){toast(e.message);}
};
document.addEventListener("keydown",e=>{if(e.key==="/"&&!document.querySelector("dialog[open]")&&!/INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName)){e.preventDefault();$("search").focus();}if(e.key==="Escape")$("detail-drawer").classList.add("hidden");});

async function init(){
  try{const remembered=JSON.parse(localStorage.getItem("mikrotik-trafficlog-connection")||"null");if(remembered?.username)$("router-user").value=remembered.username;}catch{}
  try{const bootstrap=await(await fetch("/api/bootstrap")).json();state.token=bootstrap.token;$("router-address").value=bootstrap.address || "";updateTLSOption();await poll();setInterval(poll,1000);}catch{toast("Application unavailable.");}
  renderTraffic();renderStatus();
}
init();
