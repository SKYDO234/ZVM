/* Self-hosted scripts only. No demo data, fabricated time series, or host command runner. */
'use strict';
(() => {
  const $ = (s, root = document) => root.querySelector(s);
  const $$ = (s, root = document) => [...root.querySelectorAll(s)];
  const icons = () => window.lucide?.createIcons({attrs: {'stroke-width': 1.65}});
  icons();
  const token = $('meta[name="csrf-token"]')?.content;
  // Browser Back must not restore stale VM state or a permanently locked submit
  // button from bfcache after an operation changed/deleted the instance.
  window.addEventListener('pageshow', event => {
    if (event.persisted && ($('[data-instance-action]') || $('[data-job-id]'))) location.reload();
  });
  const updateStatus = data => {
    $$('[data-instance-status]').filter(el=>el.dataset.instanceStatus===data.id).forEach(el=>{
      const state=String(data.status||'unknown');el.className='status status-'+state.replace(/[^a-z_-]/gi,'');
      const dot=document.createElement('span');dot.className='status-dot';
      el.replaceChildren(dot,document.createTextNode(state.replaceAll('_',' ').replace(/^./,x=>x.toUpperCase())));
    });
    // Hints come from the same server policy as the initial HTML. Authorization
    // and verified state transitions still happen independently in the worker.
    $$('form[data-instance-action]').filter(form=>form.dataset.instanceId===data.id).forEach(form=>{
      const control=data.controls?.[form.dataset.instanceAction], button=$('button[type="submit"]',form);
      if (!control || !button || form.dataset.submitting==='yes') return;
      button.disabled=!control.enabled; button.title=control.reason||'';
    });
    $$('[data-operation-blockers]').filter(el=>el.dataset.operationBlockers===data.id).forEach(panel=>{
      const rows=Array.isArray(data.blocking_jobs)?data.blocking_jobs:[];
      panel.hidden=rows.length===0;
      const signature=JSON.stringify(rows);
      if(panel.dataset.signature===signature)return;
      panel.dataset.signature=signature;
      const root=$('[data-operation-items]',panel);root.replaceChildren();
      for(const row of rows){
        const item=document.createElement('div');item.className='operation-item';
        const label=document.createElement('span');
        label.textContent=String(row.kind).replaceAll('_',' ')+' · #'+String(row.id).slice(0,8)+' · '+String(row.status);
        item.append(label);
        if(typeof row.url==='string'&&row.url.startsWith('/')&&!row.url.startsWith('//')){
          const link=document.createElement('a');link.className='text-link';link.href=row.url;link.textContent='Open job';item.append(link);
        }else{const hint=document.createElement('span');hint.className='muted';hint.textContent='Administrator review required.';item.append(hint);}
        root.append(item);
      }
    });
    $$('[data-lifecycle-notice]').filter(el=>el.dataset.lifecycleNotice===data.id).forEach(el=>{
      el.textContent=data.control_notice||'';el.hidden=!data.control_notice;
    });
  };

  const toast = (message, type = 'success') => {
    const el = document.createElement('div'); el.className = `toast toast-${type}`;
    const icon = document.createElement('i'); icon.dataset.lucide = type === 'success' ? 'circle-check' : 'circle-alert';
    const text = document.createElement('span'); text.textContent = message;
    const close = document.createElement('button'); close.className = 'toast-close'; close.ariaLabel = 'Dismiss'; close.textContent = '×';
    close.onclick = () => el.remove(); el.append(icon, text, close); $('#toast-stack')?.append(el); icons();
    if (type !== 'error') setTimeout(() => el.remove(), 8000);
  };
  $$('.toast-close').forEach(b => b.addEventListener('click', () => b.closest('.toast').remove()));
  const api = async (url, options = {}) => {
    const res = await fetch(url, {cache: 'no-store', credentials: 'same-origin', ...options,
      headers: {'Content-Type': 'application/json', 'X-CSRFToken': token, ...options.headers}});
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `Request failed (${res.status}).`);
    return data;
  };
  const sidebar = $('#sidebar'), shade = $('#sidebar-shade');
  $('#menu-toggle')?.addEventListener('click', () => { sidebar.classList.toggle('open'); shade.classList.toggle('open'); });
  shade?.addEventListener('click', () => {sidebar.classList.remove('open'); shade.classList.remove('open');});
  document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {e.preventDefault(); $('#global-search')?.focus();}
    if (e.key === 'Escape') {sidebar?.classList.remove('open'); shade?.classList.remove('open');}
  });
  $$('.password-toggle').forEach(button => button.addEventListener('click', () => {
    const input = $('input', button.parentElement); input.type = input.type === 'password' ? 'text' : 'password';
    button.ariaLabel = input.type === 'password' ? 'Show password' : 'Hide password';
  }));
  $$('[data-copy]').forEach(button => button.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(document.getElementById(button.dataset.copy).textContent); toast('Copied to clipboard.'); }
    catch {toast('Clipboard unavailable. Select and copy the text manually.', 'error');}
  }));
  let pendingForm, pendingSubmitter;
  const dialog = $('#confirm-dialog');
  $$('form[data-confirm]').forEach(form => form.addEventListener('submit', event => {
    if (form.dataset.confirmed === 'yes') return;
    event.preventDefault(); pendingForm = form; pendingSubmitter = event.submitter;
    $('#confirm-message').textContent = form.dataset.confirm; dialog.showModal();
  }));
  $('#cancel-confirm')?.addEventListener('click', () => { dialog.close(); pendingForm = null; });
  $('#accept-confirm')?.addEventListener('click', () => {
    dialog.close(); if (!pendingForm) return;
    if (pendingSubmitter?.disabled) {
      toast('This action is no longer available. Refresh the instance state and try again.', 'error');
      pendingForm = null; pendingSubmitter = null; return;
    }
    pendingForm.dataset.confirmed = 'yes'; pendingForm.requestSubmit(pendingSubmitter || undefined);
    pendingForm = null; pendingSubmitter = null;
  });
  $$('form:not(#console-input-form)').forEach(form => form.addEventListener('submit', event => {
    if (event.defaultPrevented || form.method.toLowerCase() !== 'post') return;
    if (form.dataset.submitting === 'yes') { event.preventDefault(); return; }
    form.dataset.submitting = 'yes';
    const button = event.submitter || $('button[type="submit"], button:not([type])', form);
    if (button) { button.disabled = true; button.textContent = 'Working…'; }
  }));

  // Real measurements are collected only while this page is open.
  if ($('#host-chart') && window.Chart) {
    const ctx = $('#host-chart').getContext('2d');
    const gradient = ctx.createLinearGradient(0, 0, 0, 220); gradient.addColorStop(0, '#6496ff2b'); gradient.addColorStop(1, '#6496ff00');
    const samples = [];
    Chart.defaults.font.family = 'Inter';
    const chart = new Chart(ctx, {type:'line', data:{labels:[], datasets:[
      {label:'Host CPU %',data:[],borderColor:'#689cff',backgroundColor:gradient,fill:true,tension:.35,borderWidth:1.8,pointRadius:0,pointHoverRadius:3},
      {label:'Host memory %',data:[],borderColor:'#a28ce4',backgroundColor:'transparent',tension:.35,borderWidth:1.5,pointRadius:0,pointHoverRadius:3}
    ]}, options:{responsive:true,maintainAspectRatio:false,animation:{duration:400},interaction:{mode:'index',intersect:false},
      plugins:{legend:{display:false},tooltip:{backgroundColor:'#1b2b44',titleColor:'#b1c7e6',bodyColor:'#92aed3',borderColor:'#678abd33',borderWidth:1,padding:11}},
      scales:{x:{border:{display:false},grid:{display:false},ticks:{color:'#4f6789',font:{size:8},maxTicksLimit:6,maxRotation:0}},
        y:{min:0,suggestedMax:100,border:{display:false},grid:{color:'#688ab212',drawTicks:false},ticks:{stepSize:25,color:'#4f6789',padding:10,font:{size:8},callback:v=>`${v}%`}}}}});
    const render = () => {const n = Number($('#chart-window').value);const data = samples.slice(-n);chart.data.labels = data.map(x=>x.label);chart.data.datasets[0].data = data.map(x=>x.cpu);chart.data.datasets[1].data = data.map(x=>x.ram);chart.update();};
    let metricsBusy = false;
    const refresh = async () => {
      if (metricsBusy) return; metricsBusy = true;
      const button = $('#refresh-metrics'); $('svg', button || document)?.classList.add('spin');
      try {
        const data = await api('/api/metrics'), h = data.host;
        data.instances.forEach(updateStatus);
        if($('#host-capacity-warning')) $('#host-capacity-warning').hidden=h.capacity_known;
        if($('#host-capacity-reason')) $('#host-capacity-reason').textContent=h.capacity_reason;
        if($('#host-cpu-scope')) $('#host-cpu-scope').textContent=h.cpu_scope;
        if($('#host-memory-scope')) $('#host-memory-scope').textContent=h.memory_scope;
        $$('[data-total]').forEach(el => { if (data.totals[el.dataset.total] !== undefined) el.textContent = data.totals[el.dataset.total]; });
        $('#host-cpu-value').textContent = h.cpu_percent===null?'Unavailable':`${h.cpu_percent}%`; $('#host-ram-value').textContent = `${h.ram_percent}%`;
        if ($('#host-cpu-bar')) $('#host-cpu-bar').style.width = `${Math.min(100,h.cpu_percent)}%`;
        if ($('#host-ram-bar')) $('#host-ram-bar').style.width = `${Math.min(100,h.ram_percent)}%`;
        if ($('#host-memory-label')) $('#host-memory-label').textContent = `${h.ram_used_mb} / ${h.ram_total_mb} MiB`;
        if ($('#host-disk-label')) $('#host-disk-label').textContent = `${h.disk_free_gb} GiB free`;
        samples.push({label:new Date(h.sampled_at*1000).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit',second:'2-digit'}), cpu:h.cpu_percent,ram:h.ram_percent});
        if (samples.length>60) samples.shift(); if (samples.length>=2) $('#chart-awaiting').hidden = true; render();
      } catch (error) { if (!document.hidden) toast(error.message, 'error'); }
      finally {metricsBusy=false; $('svg', button || document)?.classList.remove('spin');}
    };
    refresh(); setInterval(() => {if (!document.hidden) refresh();},5000);
    $('#refresh-metrics')?.addEventListener('click',()=>location.reload()); $('#chart-window')?.addEventListener('change',render);
  }
  const guest = $('[data-instance-metrics]');
  if (guest && window.Chart) {
    const chart = new Chart($('#guest-chart'), {type:'line', data:{labels:[], datasets:[
      {label:'Process CPU %',data:[],borderColor:'#689cff',borderWidth:1.8,pointRadius:0,tension:.3,yAxisID:'cpu'},
      {label:'RSS / cgroup MiB',data:[],borderColor:'#a28ce4',borderWidth:1.8,pointRadius:0,tension:.3,yAxisID:'ram'}
    ]},options:{responsive:true,maintainAspectRatio:false,animation:false,plugins:{legend:{labels:{color:'#7d99c0',font:{size:9},boxWidth:8,boxHeight:3}}},
      scales:{x:{grid:{display:false},ticks:{color:'#587397',font:{size:8},maxTicksLimit:6}},cpu:{beginAtZero:true,position:'left',suggestedMax:100,grid:{color:'#688ab212'},ticks:{color:'#689cff',font:{size:8},callback:v=>v+'%'}},ram:{beginAtZero:true,position:'right',grid:{drawOnChartArea:false},ticks:{color:'#a28ce4',font:{size:8},callback:v=>v+' MiB'}}}}});
    let busy=false;
    const refresh=async()=>{if(busy)return;busy=true;try{const data=await api('/api/vps/'+guest.dataset.instanceMetrics+'/metrics');const u=data.usage;updateStatus(data);
      $('#guest-rss').textContent=u.process_rss_mb??'Unavailable';$('#guest-cpu').textContent=u.process_cpu_percent==null?'Awaiting another sample':u.process_cpu_percent+'%';$('#guest-disk').textContent=u.disk_actual_bytes==null?'Unavailable':(u.disk_actual_bytes/1048576).toFixed(1)+' MiB';
      chart.data.labels.push(new Date().toLocaleTimeString());chart.data.datasets[0].data.push(u.process_cpu_percent??null);chart.data.datasets[1].data.push(u.process_rss_mb??null);
      if(chart.data.labels.length>60){chart.data.labels.shift();chart.data.datasets.forEach(d=>d.data.shift());}chart.update();
    }catch(error){toast(error.message,'error');}finally{busy=false;}};refresh();setInterval(()=>{if(!document.hidden)refresh();},5000);
  }
  const create = $('#create-form');
  if (create) {
    const update = () => {
      const qemu = $('input[name="engine"]:checked',create).value==='qemu';
      $$('.qemu-only',create).forEach(el=>{el.hidden=!qemu;$$('input,select,textarea',el).forEach(i=>i.disabled=!qemu);});
      $$('.docker-only',create).forEach(el=>{el.hidden=qemu;$$('input',el).forEach(i=>i.disabled=qemu);});
      const key = $('#auth-method').value==='key';
      $('.key-field').hidden=!key; $('.password-auth-field').hidden=key;
      $('[name="public_key"]').required=qemu&&key; $('[name="public_key"]').disabled=!qemu||!key;
      $('[name="guest_password"]').required=qemu&&!key; $('[name="guest_password"]').disabled=!qemu||key;
      $('#ram-input').min=qemu?512:128;
      const os = $('#os-select').selectedOptions[0];
      $('#disk-input').min=qemu?(os?.dataset.minDisk||8):1;
      $('#summary-name').textContent=$('#instance-name').value||'Your new instance';
      $('#summary-engine').textContent=qemu?'QEMU VIRTUAL MACHINE':'DOCKER CONTAINER';
      $('#summary-os').textContent=os?os.textContent.split(' · ')[0]:'No enabled images';
      [['ram','ram'],['cpu','cpu'],['disk','disk']].forEach(([target,input])=>$('#summary-'+target).textContent=$('#'+input+'-input').value||'—');
      const warning=$('#engine-warning');$('span',warning).textContent=$('#node-select').value==='local'?(qemu?warning.dataset.qemuReason:warning.dataset.dockerReason):'External node capacity and engine availability are checked by its authenticated agent.';
      $('#eol-ack').hidden=!os?.dataset.eol; $('#eol-text').textContent=os?.dataset.eol?os.dataset.eol+' I acknowledge this warning.':'';
    };
    create.addEventListener('input',update);create.addEventListener('change',event=>{if(event.target.id==='os-select')$('#guest-username').value=event.target.selectedOptions[0].dataset.user;update();});
    $$('[data-ram]').forEach(b=>b.addEventListener('click',()=>{$('#ram-input').value=b.dataset.ram;$$('[data-ram]').forEach(x=>x.classList.toggle('selected',x===b));update();}));update();
  }
  $$('[data-engine-filter]').forEach(button=>button.addEventListener('click',()=>{
    $$('[data-engine-filter]').forEach(x=>x.classList.toggle('active',x===button));let count=0;
    $$('.vps-card[data-engine]').forEach(card=>{card.hidden=button.dataset.engineFilter!=='all'&&button.dataset.engineFilter!==card.dataset.engine;if(!card.hidden)count++;});
    if($('#filter-empty'))$('#filter-empty').hidden=count>0;
  }));
  const job = $('[data-job-id]');
  if(job){let timer;const poll=async()=>{try{const data=await api('/api/jobs/'+job.dataset.jobId);$('#job-state').className='status status-'+data.status;$('#job-state').textContent=data.status[0].toUpperCase()+data.status.slice(1);$('#job-message').textContent=data.message;$('#job-instance-link').hidden=!data.exists;
      if($('#job-uncertain-help'))$('#job-uncertain-help').hidden=data.status!=='uncertain';
      $$('[data-job-recovery]',job).forEach(form=>{const available=data[form.dataset.jobRecovery]===true;form.hidden=!available;const button=$('button',form);if(button&&form.dataset.submitting!=='yes')button.disabled=!available;});if(!['queued','running'].includes(data.status)){clearInterval(timer);$('#job-symbol').classList.remove('spin');}}catch(error){clearInterval(timer);toast(error.message,'error');}};timer=setInterval(poll,2000);poll();}
  const drawer=$('#activity-drawer');
  $('#notifications-toggle')?.addEventListener('click',async()=>{drawer.hidden=!drawer.hidden;if(drawer.hidden)return;try{const rows=await api('/api/activity');const root=$('#activity-items');root.replaceChildren();if(!rows.length)root.textContent='No activity recorded yet.';for(const row of rows){const el=document.createElement('div');el.className='drawer-item';const text=document.createElement('span');text.textContent=row.message;const date=document.createElement('small');date.textContent=new Date(row.at).toLocaleString();el.append(text,date);root.append(el);}}catch(error){$('#activity-items').textContent=error.message;}});
  $('#close-activity')?.addEventListener('click',()=>drawer.hidden=true);
  const enrollMethod = document.getElementById('enroll-method');
  if (enrollMethod) {
    const update = () => {
      const key = enrollMethod.value === 'key';
      for (const [selector, active] of [['[data-enroll-password]', !key], ['[data-enroll-key]', key]]) {
        const section = document.querySelector(selector); section.hidden = !active;
        section.querySelectorAll('input,textarea').forEach(field => { field.disabled = !active; field.required = active && field.name !== 'passphrase'; });
      }
    };
    enrollMethod.addEventListener('change', update); update();
  }
  const sshxTask = document.querySelector('[data-sshx-job]');
  if (sshxTask) {
    let timer;
    const poll = async () => {
      if (document.hidden) return;
      try {
        const data = await api('/api/jobs/' + sshxTask.dataset.sshxJob);
        if (!['queued','running'].includes(data.status)) {
          clearInterval(timer);
          if (data.status !== sshxTask.dataset.initialStatus) location.reload();
        }
      } catch (error) { clearInterval(timer); toast(error.message, 'error'); }
    };
    timer = setInterval(poll, 2000); poll();
  }
})();
