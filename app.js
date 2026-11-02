'use strict';
// Badr Vault: local-only educational prototype. No analytics, network requests, or remote dependencies.
const DB_NAME = 'badr-vault-data-v1';
const DB_STORE = 'private';
const FORMAT = 'badr-vault';
const KDF_ITERATIONS = 600000;
const LOCK_DELAY_MS = 5 * 60 * 1000;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', {fatal:true});
const $ = id => document.getElementById(id);
const elements = {
  authScreen:$('auth-screen'),main:$('main-screen'), authForm:$('auth-form'),
  master:$('master'), confirm:$('master-confirm'), authError:$('auth-error'),
  authSubmit:$('auth-submit'), authTitle:$('auth-title'), authSubtitle:$('auth-subtitle'),
  editor:$('editor-backdrop'), detail:$('detail-backdrop'), change:$('change-backdrop'),
  entryList:$('entry-list'), search:$('search'), toast:$('toast')
};
let db = null;
let vaultMeta = null; // Encrypted record only
let entries = [];
let key = null; // WebCrypto non-extractable CryptoKey; only kept in memory until lock
let screen = 'vault';
let filter = 'all';
let selectedId = null;
let authMode = 'setup';
let generation = '';
let idleTimeout = null;
let toastTimeout = null;
let isBusy = false;
let isSaving = false;

function visibility(el, visible) { el.classList.toggle('hidden', !visible); }
function showToast(message) {
  elements.toast.textContent = message;
  visibility(elements.toast, true);
  clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => visibility(elements.toast, false), 2600);
}
function showError(el, message) { el.textContent = message; visibility(el, !!message); }
function randomBytes(count) { const bytes = new Uint8Array(count); crypto.getRandomValues(bytes); return bytes; }
function encode64(bytes) {
  let raw = '';
  for (let i = 0; i < bytes.length; i += 8192) raw += String.fromCharCode(...bytes.subarray(i,i+8192));
  return btoa(raw);
}
function decode64(str) { const raw = atob(str); return Uint8Array.from(raw, ch => ch.charCodeAt(0)); }
function randomInt(max) {
  const size = 4294967296;
  const limit = Math.floor(size/max) * max;
  const buf = new Uint32Array(1);
  let n;
  do { crypto.getRandomValues(buf); n = buf[0]; } while(n >= limit);
  return n % max;
}
const alphabets = {
  upper:'ABCDEFGHJKLMNPQRSTUVWXYZ',
  lower:'abcdefghijkmnopqrstuvwxyz',
  numbers:'23456789',
  symbols:'!@#$%^&*()-_=+?'
};
function makePassword(length, chosen) {
  const sets = chosen.map(x => alphabets[x]).filter(Boolean);
  if (!sets.length) throw new Error('Choose at least one character type.');
  const all = sets.join('');
  const chars = sets.map(s => s[randomInt(s.length)]);
  while(chars.length < length) chars.push(all[randomInt(all.length)]);
  for(let i = chars.length-1; i > 0; i--) {
    const j = randomInt(i+1);
    [chars[i],chars[j]] = [chars[j],chars[i]];
  }
  return chars.join('');
}
async function deriveKey(master, salt, iterations) {
  const material = await crypto.subtle.importKey('raw',encoder.encode(master),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt,iterations},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
function recordIsValid(record) {
  return record && record.format===FORMAT && record.version===1 && record.kdf==='PBKDF2-SHA256' &&
    Number.isSafeInteger(record.iterations) && record.iterations>=310000 && record.iterations<=1000000 &&
    typeof record.salt==='string' && record.salt.length===24 &&
    typeof record.iv==='string' && record.iv.length===16 &&
    typeof record.ciphertext==='string' && record.ciphertext.length>=20 && record.ciphertext.length<=9000000;
}
function sanitizeEntries(untrusted) {
  if (!untrusted || untrusted.version !== 1 || !Array.isArray(untrusted.entries) || untrusted.entries.length>10000) throw new Error('Unsupported or damaged vault.');
  for(const item of untrusted.entries){
    if(!item || typeof item.id!=='string' || typeof item.title!=='string' || typeof item.password!=='string' ||
      typeof item.username!=='string' || typeof item.website!=='string' || typeof item.notes!=='string' ||
      item.title.length>120 || item.password.length>512 || item.username.length>250 || item.website.length>300 || item.notes.length>2000)
      throw new Error('Unsupported or damaged entries.');
  }
  return untrusted.entries.map(item => ({
    id:item.id, title:item.title, username:item.username, website:item.website, password:item.password,
    notes:item.notes, favorite:!!item.favorite, updatedAt:Number(item.updatedAt)||Date.now()
  }));
}
async function encryptRecord(currentKey, currentEntries, originalMeta) {
  const iv = randomBytes(12);
  const plaintext = encoder.encode(JSON.stringify({version:1,entries:currentEntries}));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv},currentKey,plaintext));
  return {
    format:FORMAT,version:1,kdf:'PBKDF2-SHA256', iterations:originalMeta.iterations,
    salt:originalMeta.salt, iv:encode64(iv), ciphertext:encode64(ciphertext),
    updatedAt:new Date().toISOString()
  };
}
async function decryptRecord(record, currentKey) {
  if (!recordIsValid(record)) throw new Error('Unsupported or damaged backup.');
  const decrypted = await crypto.subtle.decrypt({name:'AES-GCM',iv:decode64(record.iv)},currentKey,decode64(record.ciphertext));
  return sanitizeEntries(JSON.parse(decoder.decode(decrypted)));
}
function getDB() {
  return new Promise((resolve,reject) => {
    const request = indexedDB.open(DB_NAME,1);
    request.onupgradeneeded = () => {
      if(!request.result.objectStoreNames.contains(DB_STORE)) request.result.createObjectStore(DB_STORE);
    };
    request.onsuccess=()=>resolve(request.result);
    request.onerror=()=>reject(request.error);
  });
}
function getRecord() {
  return new Promise((resolve,reject) => {
    const req = db.transaction(DB_STORE,'readonly').objectStore(DB_STORE).get('vault');
    req.onsuccess=()=>resolve(req.result||null);
    req.onerror=()=>reject(req.error);
  });
}
function putRecord(record) {
  return new Promise((resolve,reject)=>{
    const tx = db.transaction(DB_STORE,'readwrite');
    tx.objectStore(DB_STORE).put(record,'vault');
    tx.oncomplete=resolve;
    tx.onerror=()=>reject(tx.error);
    tx.onabort=()=>reject(tx.error||new Error('Storage failed.'));
  });
}
async function persist() {
  if (isSaving || !key) throw new Error('Vault is locked or still saving.');
  isSaving=true;
  try {
    const nextRecord=await encryptRecord(key,entries,vaultMeta);
    await putRecord(nextRecord);
    vaultMeta=nextRecord;
  } finally { isSaving=false; }
}
function resetIdleTimeout() {
  if(!key) return;
  clearTimeout(idleTimeout);
  idleTimeout=setTimeout(()=>lock('Vault locked after 5 minutes of inactivity.'),LOCK_DELAY_MS);
}
function toggleBusy(busy) {
  isBusy=busy;
  elements.authSubmit.disabled=busy;
  $('save-entry').disabled=busy;
  $('change-save').disabled=busy;
  elements.authSubmit.textContent=busy?'Working securely…':(authMode==='setup'?'Create encrypted vault →':'Unlock vault →');
}
async function init() {
  if(!window.isSecureContext || !window.crypto?.subtle || !window.indexedDB) {
    visibility($('unavailable'),true); return;
  }
  try {
    db=await getDB(); vaultMeta=await getRecord();
    setAuthMode(vaultMeta?'unlock':'setup');
    visibility(elements.authScreen,true);
  } catch(e) {
    visibility($('unavailable'),true);
    $('unavailable').querySelector('p').textContent='Local storage is unavailable. Check Safari privacy settings and open the app in a normal browser window.';
  }
  if('serviceWorker' in navigator) navigator.serviceWorker.register('./sw.js').catch(()=>{});
}
function setAuthMode(mode) {
  authMode=mode;
  const setup=mode==='setup';
  elements.authTitle.textContent=setup?'Your digital safe.':'Welcome back.';
  elements.authSubtitle.textContent=setup?'Create one strong master password. Your saved accounts will be encrypted and kept only on this device.':'Enter your master password to unlock your encrypted accounts.';
  visibility($('confirm-wrap'),setup);
  elements.master.minLength=setup?12:1;
  elements.master.value='';elements.confirm.value='';
  $('toggle-master').textContent='Show';elements.master.type='password';
  showError(elements.authError,'');
  elements.authSubmit.textContent=setup?'Create encrypted vault →':'Unlock vault →';
}
async function tryStoragePersistence() {
  try { if(navigator.storage?.persist) await navigator.storage.persist(); } catch(_) {}
}
async function submitAuth(event) {
  event.preventDefault(); if(isBusy) return;
  const password=elements.master.value;
  if(authMode==='setup') {
    if(password.length<12) return showError(elements.authError,'Use at least 12 characters for your master password.');
    if(password!==elements.confirm.value) return showError(elements.authError,'The two master passwords do not match.');
    if(!confirm('Important: no one can recover your master password. Save it somewhere safe. Create the vault?')) return;
  }
  toggleBusy(true); showError(elements.authError,'');
  try {
    if(authMode==='setup') {
      if(await getRecord()) throw new Error('Vault already exists on this device.');
      const salt=randomBytes(16);
      const newKey=await deriveKey(password,salt,KDF_ITERATIONS);
      const meta={iterations:KDF_ITERATIONS,salt:encode64(salt)};
      const rec=await encryptRecord(newKey,[],meta);
      await putRecord(rec);
      vaultMeta=rec;key=newKey;entries=[];
      await tryStoragePersistence();
      showToast('Encrypted vault created');
    } else {
      if(!recordIsValid(vaultMeta)) throw new Error('Vault data is damaged or unsupported.');
      const newKey=await deriveKey(password,decode64(vaultMeta.salt),vaultMeta.iterations);
      let decoded;
      try {decoded=await decryptRecord(vaultMeta,newKey);} catch(_) {throw new Error('Incorrect master password or damaged vault.');}
      entries=decoded; key=newKey;
      showToast('Vault unlocked');
    }
    elements.master.value='';elements.confirm.value='';
    visibility(elements.authScreen,false);visibility(elements.main,true);visibility($('bottom-nav'),true);
    showPage('vault');renderEntries();resetIdleTimeout();
  } catch(e) {showError(elements.authError,e.message||'Cannot open the vault.');}
  finally {elements.master.value='';elements.confirm.value='';toggleBusy(false);}
}
function lock(message) {
  if(!key) return;
  key=null;entries=[];generation='';selectedId=null;screen='vault';
  clearTimeout(idleTimeout);clearTimeout(toastTimeout);
  visibility(elements.editor,false);visibility(elements.detail,false);visibility(elements.change,false);
  elements.entryList.replaceChildren();elements.search.value='';
  $('generated-password').value='';$('edit-password').value='';
  $('change-old').value='';$('change-new').value='';$('change-confirm').value='';
  visibility(elements.main,false);visibility($('bottom-nav'),false);
  setAuthMode('unlock');visibility(elements.authScreen,true);
  if(message)showToast(message);
}
function showPage(name) {
  screen=name;
  for(const page of ['vault','generator','settings']) visibility($('page-'+page),name===page);
  document.querySelectorAll('.nav-item').forEach(button=>button.classList.toggle('active',button.dataset.page===name));
  if(name==='generator' && !generation) generate();
  window.scrollTo({top:0,behavior:'instant'});
}
function initials(title) {return title.trim().split(/\s+/).slice(0,2).map(s=>s[0]||'').join('').toUpperCase()||'•';}
function create(tag,classname,text){const node=document.createElement(tag);if(classname)node.className=classname;if(text!==undefined)node.textContent=text;return node;}
function renderEntries() {
  if(!key)return;
  const term=elements.search.value.trim().toLocaleLowerCase();
  const filtered=entries.filter(e=>
    (filter!=='favorites'||e.favorite) &&
    [e.title,e.username,e.website].some(s=>s.toLocaleLowerCase().includes(term))
  ).sort((a,b)=>a.title.localeCompare(b.title));
  elements.entryList.replaceChildren();
  for(const entry of filtered){
    const card=create('button','entry-card'); card.type='button';card.setAttribute('aria-label','View '+entry.title);
    const avatar=create('span','entry-avatar',initials(entry.title));
    const info=create('span','entry-meta');
    const name=create('div','entry-name');
    if(entry.favorite) name.append(create('span','favorite-star','★ '));
    name.append(document.createTextNode(entry.title));
    info.append(name,create('div','entry-sub',entry.username||entry.website||'Saved account'));
    card.append(avatar,info,create('span','entry-trail','›'));
    card.addEventListener('click',()=>openDetail(entry.id));
    elements.entryList.append(card);
  }
  $('entry-count').textContent=String(entries.length);
  visibility($('empty-state'),filtered.length===0);
  $('empty-state').querySelector('h3').textContent=entries.length===0?'No passwords here yet':'No matching accounts';
  $('empty-state').querySelector('p').textContent=entries.length===0?'Add your first login to begin building your encrypted vault.':'Try a different search or filter.';
}
function openEditor(id=null, password='') {
  if(!key)return;
  const e=id?entries.find(item=>item.id===id):null;
  $('editor-title').textContent=e?'Edit account':'New account';
  $('edit-id').value=e?.id||'';
  $('edit-title').value=e?.title||'';
  $('edit-user').value=e?.username||'';
  $('edit-password').value=e?.password||password;
  $('edit-site').value=e?.website||'';
  $('edit-notes').value=e?.notes||'';
  $('edit-favorite').checked=!!e?.favorite;
  $('edit-password').type='password';$('toggle-edit').textContent='Show';
  visibility($('delete-entry'),!!e);
  visibility(elements.detail,false);
  visibility(elements.editor,true);
  $('edit-title').focus();
}
function closeEditor(){visibility(elements.editor,false);$('edit-password').value='';}
async function submitEntry(event) {
  event.preventDefault();if(isBusy||isSaving||!key)return;
  const title=$('edit-title').value.trim();
  const password=$('edit-password').value;
  if(!title||!password) return showToast('Enter an account name and password.');
  const id=$('edit-id').value;
  const old=id?entries.find(e=>e.id===id):null;
  const entry={id:old?.id||crypto.randomUUID(),title,username:$('edit-user').value.trim(),password,
    website:$('edit-site').value.trim(),notes:$('edit-notes').value.trim(),favorite:$('edit-favorite').checked,updatedAt:Date.now()};
  const previous=entries;
  entries=old?entries.map(e=>e.id===old.id?entry:e):[...entries,entry];
  toggleBusy(true);
  try{await persist();closeEditor();renderEntries();showToast('Account saved securely');}
  catch(e){entries=previous;showToast('Could not save. Check device storage.');}
  finally{toggleBusy(false);}
}
async function deleteEntry() {
  const id=$('edit-id').value;
  if(!id||!key||isSaving||!confirm('Permanently delete this saved account?'))return;
  const previous=entries;
  entries=entries.filter(e=>e.id!==id);
  try{await persist();closeEditor();renderEntries();showToast('Account deleted');}
  catch(e){entries=previous;showToast('Delete failed. Please try again.');}
}
function detailRow(label, value, options={}){
  const block=create('div','detail-block');block.append(create('div','detail-label',label));
  const flex=create('div','detail-flex');const data=create('div','detail-value'+(options.mask?' mask':''),options.mask?'••••••••••••':value||'—');
  flex.append(data);
  if(options.copy){const copy=create('button','detail-control','Copy');copy.type='button';copy.addEventListener('click',()=>copyValue(value));flex.append(copy);}
  if(options.mask){
    const reveal=create('button','detail-control','Show');reveal.type='button';
    reveal.addEventListener('click',()=>{
      const showing=reveal.textContent==='Hide';
      data.textContent=showing?'••••••••••••':value;
      data.classList.toggle('mask',showing);
      reveal.textContent=showing?'Show':'Hide';
    });
    flex.append(reveal);
  }
  block.append(flex);return block;
}
function openDetail(id) {
  if(!key)return;
  const e=entries.find(x=>x.id===id);if(!e)return;
  selectedId=e.id;
  $('detail-title').textContent=e.title;
  $('detail-content').replaceChildren(
    detailRow('USERNAME / EMAIL',e.username,{copy:!!e.username}),
    detailRow('PASSWORD',e.password,{mask:true,copy:true}),
    detailRow('WEBSITE',e.website,{copy:!!e.website}),
    ...(e.notes?[detailRow('NOTES',e.notes)]:[])
  );
  visibility(elements.detail,true);
}
async function copyValue(value) {
  if(!key)return;
  try{await navigator.clipboard.writeText(value);showToast('Copied to clipboard');}
  catch(e){
    try{
      const temp=create('textarea');temp.value=value;temp.style.position='fixed';temp.style.left='-9999px';
      document.body.append(temp);temp.select();const success=document.execCommand('copy');temp.remove();
      showToast(success?'Copied to clipboard':'Unable to copy on this browser');
    } catch (_) {showToast('Clipboard is unavailable');}
  }
}
function chosenSets(){return ['upper','lower','numbers','symbols'].filter(s=>$('opt-'+s).checked);}
function generate(){
  try {
    generation=makePassword(Number($('gen-length').value),chosenSets());
    $('generated-password').value=generation;
    const poolSize=chosenSets().reduce((sum,s)=>sum+alphabets[s].length,0);
    const bits=generation.length*Math.log2(poolSize);
    $('strength-label').textContent=bits>=100?'Excellent random password':bits>=75?'Very strong random password':bits>=60?'Strong random password':'Use a longer password for better security';
    const bars=bits>=100?4:bits>=75?3:bits>=60?2:1;
    document.querySelectorAll('.strength-bars i').forEach((el,i)=>el.classList.toggle('inactive',i>=bars));
  } catch(e){generation='';$('generated-password').value='';showToast(e.message);}
}
async function exportBackup(){
  if(!key||!vaultMeta)return;
  try {
    const filename='badr-vault-backup-'+new Date().toISOString().slice(0,10)+'.json';
    const file=new File([JSON.stringify(vaultMeta,null,2)],filename,{type:'application/json'});
    // iOS can save the encrypted file to Files from the native share sheet.
    if(navigator.canShare?.({files:[file]})){
      try {await navigator.share({files:[file],title:'Badr Vault encrypted backup'});showToast('Encrypted backup shared');}
      catch(e){if(e.name!=='AbortError')showToast('Backup sharing failed');}
      return;
    }
    const url=URL.createObjectURL(file);
    const link=document.createElement('a');
    link.href=url;link.download=filename;
    document.body.append(link);link.click();link.remove();
    setTimeout(()=>URL.revokeObjectURL(url),15000);
    showToast('Encrypted backup downloaded');
  } catch(e){showToast('Could not export backup');}
}
async function importBackup(file) {
  if(!file)return;
  if(file.size>7000000) return showToast('Backup file is too large');
  let candidate;
  try{
    candidate=JSON.parse(await file.text());
    if(!recordIsValid(candidate))throw Error('Invalid backup');
    if(decode64(candidate.salt).length!==16||decode64(candidate.iv).length!==12)throw Error('Invalid backup');
  }catch(e){return showToast('Not a valid encrypted Badr Vault backup');}
  const warning=vaultMeta?'This will REPLACE every account saved on this device. Export your existing vault first. Continue?':'Restore this encrypted backup to this device?';
  if(!confirm(warning))return;
  if(vaultMeta&&!confirm('Final confirmation: all current local passwords will be replaced. Continue?'))return;
  try{
    await putRecord(candidate);vaultMeta=candidate;
    if(key)lock();
    setAuthMode('unlock');visibility(elements.authScreen,true);
    visibility(elements.main,false);visibility($('bottom-nav'),false);
    showToast('Backup imported. Unlock using its original master password.');
  }catch(e){showToast('Import failed; no changes made');}
}
async function submitChange(event) {
  event.preventDefault();if(isBusy||!key)return;
  const old=$('change-old').value, next=$('change-new').value, confirmation=$('change-confirm').value;
  if(next.length<12)return showError($('change-error'),'New master password must contain at least 12 characters.');
  if(next!==confirmation)return showError($('change-error'),'New master passwords do not match.');
  toggleBusy(true);showError($('change-error'),'');
  try {
    const check=await deriveKey(old,decode64(vaultMeta.salt),vaultMeta.iterations);
    try{await decryptRecord(vaultMeta,check);}catch(_){throw new Error('Current master password is incorrect.');}
    const salt=randomBytes(16);
    const nextKey=await deriveKey(next,salt,KDF_ITERATIONS);
    const rec=await encryptRecord(nextKey,entries,{salt:encode64(salt),iterations:KDF_ITERATIONS});
    await putRecord(rec);
    key=nextKey;vaultMeta=rec;
    visibility(elements.change,false);
    $('change-old').value='';$('change-new').value='';$('change-confirm').value='';
    showToast('Master password updated. Make a fresh backup.');
  } catch(e){showError($('change-error'),e.message||'Unable to change master password.');}
  finally{toggleBusy(false);}
}
// Explicit user interactions only. No password or account data ever leaves through fetch/XHR.
elements.authForm.addEventListener('submit',submitAuth);
$('toggle-master').addEventListener('click',()=>{const showing=elements.master.type==='text';elements.master.type=showing?'password':'text';$('toggle-master').textContent=showing?'Show':'Hide';});
$('toggle-edit').addEventListener('click',()=>{const field=$('edit-password');field.type=field.type==='password'?'text':'password';$('toggle-edit').textContent=field.type==='text'?'Hide':'Show';});
$('auth-import').addEventListener('click',()=>$('backup-input').click());
$('backup-input').addEventListener('change',async e=>{const file=e.target.files?.[0];e.target.value='';await importBackup(file);});
$('add-top').addEventListener('click',()=>openEditor());
$('empty-add').addEventListener('click',()=>openEditor());
$('header-lock').addEventListener('click',()=>lock('Vault locked'));
$('lock-btn').addEventListener('click',()=>lock('Vault locked'));
elements.search.addEventListener('input',renderEntries);
document.querySelectorAll('.filter').forEach(button=>button.addEventListener('click',()=>{
  filter=button.dataset.filter;
  document.querySelectorAll('.filter').forEach(b=>b.classList.toggle('active',b===button));renderEntries();
}));
document.querySelectorAll('.nav-item').forEach(button=>button.addEventListener('click',()=>{if(key)showPage(button.dataset.page);}));
$('editor-form').addEventListener('submit',submitEntry);
$('close-editor').addEventListener('click',closeEditor);
$('delete-entry').addEventListener('click',deleteEntry);
$('editor-generate').addEventListener('click',()=>{
  $('edit-password').value=makePassword(20,Object.keys(alphabets));
  $('edit-password').type='text';$('toggle-edit').textContent='Hide';
  showToast('Unique password generated. Save your account.');
});
$('close-detail').addEventListener('click',()=>visibility(elements.detail,false));
$('detail-edit').addEventListener('click',()=>openEditor(selectedId));
$('gen-length').addEventListener('input',()=>{$('gen-length-value').textContent=$('gen-length').value;generate();});
for(const s of Object.keys(alphabets))$('opt-'+s).addEventListener('change',generate);
$('gen-again').addEventListener('click',generate);
$('gen-copy').addEventListener('click',()=>{if(generation)copyValue(generation);else showToast('Generate a password first');});
$('gen-save').addEventListener('click',()=>{if(generation)openEditor(null,generation);else showToast('Generate a password first');});
$('export-btn').addEventListener('click',exportBackup);
$('import-btn').addEventListener('click',()=>$('backup-input').click());
$('change-master').addEventListener('click',()=>{showError($('change-error'),'');visibility(elements.change,true);});
$('change-form').addEventListener('submit',submitChange);
$('close-change').addEventListener('click',()=>{
  $('change-old').value='';$('change-new').value='';$('change-confirm').value='';visibility(elements.change,false);
});
for (const overlay of [elements.editor,elements.detail,elements.change]){
  overlay.addEventListener('click',e=>{if(e.target===overlay){
    if(overlay===elements.editor)closeEditor();
    else visibility(overlay,false);
  }});
}
document.addEventListener('visibilitychange',()=>{if(document.hidden)lock();});
for(const type of ['pointerdown','keydown','touchstart'])document.addEventListener(type,resetIdleTimeout,{passive:true});
init();
