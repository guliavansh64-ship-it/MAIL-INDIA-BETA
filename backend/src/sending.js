'use strict';
const crypto=require('node:crypto');
const nodemailer=require('nodemailer');
const {projectLog}=require('./logs');
const sha=s=>crypto.createHash('sha256').update(String(s||'').toLowerCase().trim()).digest('hex');

function keyBuffer(k){let b;try{b=Buffer.from(k||'','base64')}catch{}if(!b||b.length!==32){if(process.env.SENDER_ENCRYPTION_KEY&&Buffer.from(process.env.SENDER_ENCRYPTION_KEY,'base64').length===32){return Buffer.from(process.env.SENDER_ENCRYPTION_KEY,'base64');}return crypto.createHash('sha256').update(process.env.SESSION_SECRET||'mailbridge-master-session-salt-375ee').digest();}return b}
function encryptCredentials(key,id,data){let iv=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',keyBuffer(key),iv);cipher.setAAD(Buffer.from(id));let body=Buffer.concat([cipher.update(JSON.stringify(data),'utf8'),cipher.final()]);return {iv:iv.toString('base64'),ciphertext:body.toString('base64'),tag:cipher.getAuthTag().toString('base64')}}
function decryptCredentials(key,id,data){let d=crypto.createDecipheriv('aes-256-gcm',keyBuffer(key),Buffer.from(data.iv,'base64'));d.setAAD(Buffer.from(id));d.setAuthTag(Buffer.from(data.tag,'base64'));return JSON.parse(Buffer.concat([d.update(Buffer.from(data.ciphertext,'base64')),d.final()]).toString('utf8'))}
function transport(email,secret){
  const port = Number(secret.port) || (secret.secure === false ? 587 : 465);
  const secure = secret.secure !== undefined ? Boolean(secret.secure) : (port === 465);
  const authUser = secret.username || email;
  const auth = secret.type === 'oauth2'
    ? { type: 'OAuth2', user: authUser, clientId: secret.clientId, clientSecret: secret.clientSecret, refreshToken: secret.refreshToken }
    : { user: authUser, pass: secret.password };
  return nodemailer.createTransport({
    host: secret.host || 'smtp.gmail.com',
    port,
    secure,
    auth,
    connectionTimeout: 15000,
    greetingTimeout: 15000,
    socketTimeout: 30000,
    tls: { rejectUnauthorized: secret.rejectUnauthorized !== false }
  });
}
function validEmail(s){return typeof s==='string'&&s.length<=254&&/^[^\s@<>(),;:\\"]+@[^\s@<>(),;:\\"]+\.[a-zA-Z]{2,63}$/.test(s)}
function normalize(body){
  if(!body||!validEmail(body.to)||typeof body.subject!=='string'||!body.subject.trim()||body.subject.length>200||/[\r\n]/.test(body.subject)||body.consent!==true||(!body.text&&!body.html)) throw Error('INVALID_REQUEST');
  if(body.text!==undefined&&(typeof body.text!=='string'||body.text.length>20000)) throw Error('INVALID_REQUEST');
  if(body.html!==undefined&&(typeof body.html!=='string'||body.html.length>20000)) throw Error('INVALID_REQUEST');
  const allowed=['to','subject','text','html','consent','idempotency_key','cc','bcc','replyTo','reply_to','attachments','fromName','from_name'];
  if(Object.keys(body).some(k=>!allowed.includes(k))) throw Error('INVALID_REQUEST');
  return {
    to: body.to.toLowerCase(),
    subject: body.subject.trim(),
    text: body.text || '',
    html: body.html || '',
    consent: true,
    ...(body.cc ? { cc: body.cc } : {}),
    ...(body.bcc ? { bcc: body.bcc } : {}),
    ...(body.replyTo || body.reply_to ? { replyTo: body.replyTo || body.reply_to } : {}),
    ...(Array.isArray(body.attachments) ? { attachments: body.attachments } : {}),
    ...(body.fromName || body.from_name ? { fromName: body.fromName || body.from_name } : {})
  };
}
const safeId=id=>typeof id==='string'&&/^[A-Za-z0-9_-]{1,128}$/.test(id);

// Financial state and idempotency records share a single RTDB transaction.
async function reserve(db,uid,idempotencyKey,message,senderId){
  const id=sha(idempotencyKey),fingerprint=sha(JSON.stringify(message)),now=Date.now(),ref=db.ref('wallets/'+uid);
  let result=await ref.transaction(w=>{
    if(w===null)return null;
    w=w||{balance:0,reserved:0,purchased:0,consumed:0};
    w.sendRequests=w.sendRequests||{};
    let prior=w.sendRequests[id];
    if(prior)return w;
    if(!Number.isSafeInteger(w.balance)||w.balance<1||!Number.isSafeInteger(w.reserved||0)||!Number.isSafeInteger(w.consumed||0))return;
    w.balance--;
    w.reserved=(w.reserved||0)+1;
    w.sendRequests[id]={id,status:'queued',fingerprint,message,senderId,createdAt:now};
    w.ledger=w.ledger||{};
    w.ledger['reserve_'+id]={type:'reserve',credits:-1,reference:id,createdAt:now};
    return w;
  },undefined,false);
  if(!result.committed||!result.snapshot?.val()?.sendRequests?.[id])return {error:'INSUFFICIENT_CREDITS'};
  let job=result.snapshot.val().sendRequests[id];
  if(job.fingerprint!==fingerprint)return {error:'IDEMPOTENCY_CONFLICT'};
  await projectLog(db,uid,job);
  return {id,job};
}

async function transition(db,uid,id,from,to,detail={}){
  let changed=false,now=Date.now();
  let result=await db.ref('wallets/'+uid).transaction(w=>{
    if(w===null)return null;
    changed=false;
    let job=w?.sendRequests?.[id];
    if(!job||!from.includes(job.status))return;
    job.status=to;
    job.updatedAt=now;
    Object.assign(job,detail);
    w.ledger=w.ledger||{};
    if(to==='accepted'){
      if(!Number.isSafeInteger(w.reserved)||w.reserved<1)return;
      w.reserved--;
      w.consumed=(w.consumed||0)+1;
      w.ledger['accepted_'+id]={type:'accepted',credits:0,reference:id,createdAt:now};
    }else if(to==='failed'){
      if(!Number.isSafeInteger(w.reserved)||w.reserved<1)return;
      w.reserved--;
      w.balance=(w.balance||0)+1;
      w.ledger['release_'+id]={type:'release',credits:1,reference:id,createdAt:now};
    }
    changed=true;
    return w;
  },undefined,false);
  if(result.committed&&changed){
    try{await projectLog(db,uid,result.snapshot.val().sendRequests[id]);}catch{console.error('Log projection failed; wallet remains authoritative.')}
  }
  return result.committed&&changed;
}

async function senderAttempt(db,senderId,day){
  const ref=db.ref('sender_accounts/'+senderId);
  let ok=false;
  let r=await ref.transaction(s=>{
    ok=false;
    if(s===null)return null;
    if(!s||s.status!=='active'||!Number.isSafeInteger(s.dailyLimit)||s.dailyLimit<1)return;
    s.usage=s.usage||{};
    let n=s.usage[day]||0;
    if(!Number.isSafeInteger(n)||n>=s.dailyLimit)return;
    s.usage[day]=n+1;
    ok=true;
    return s;
  },undefined,false);
  return r.committed&&ok;
}

async function runJob({db,key,uid,id,send=async(s,m,secret)=>transport(s.email,secret).sendMail(m)}){
  if(!safeId(uid)||!/^[a-f0-9]{64}$/.test(id))return;
  // Only the first worker can claim a queued request. Never re-send a processing or unknown job.
  if(!await transition(db,uid,id,['queued'],'processing'))return;
  let job=(await db.ref(`wallets/${uid}/sendRequests/${id}`).get()).val();
  let user=(await db.ref('users/'+uid).get()).val();
  if(!user||user.status!=='active'){await transition(db,uid,id,['processing'],'failed',{error:'USER_SUSPENDED'});return}
  if((await db.ref('suppression_list/'+sha(job.message.to)).get()).val()){await transition(db,uid,id,['processing'],'failed',{error:'RECIPIENT_SUPPRESSED'});return}

  // An explicit administrator assignment keeps the selected From account,
  // including when this user also connected a separate Gmail OAuth account.
  const assignment = (await db.ref(`sender_assignments/${uid}`).get()).val();
  const hasTenantPin = assignment?.manual === true && safeId(assignment.senderId);
  const systemSenderId = String(process.env.SYSTEM_SENDER_ID || '').trim();
  const pinnedSenderId = hasTenantPin ? assignment.senderId : systemSenderId;
  const isPinnedSender = Boolean(pinnedSenderId);
  if (isPinnedSender && (!safeId(pinnedSenderId) || pinnedSenderId !== job.senderId)) {
    await transition(db, uid, id, ['processing'], 'failed', { error: 'SENDER_UNAVAILABLE' });
    return;
  }
  const gmailConn = isPinnedSender ? null : (await db.ref(`gmail_connections/${uid}`).get()).val();
  if (gmailConn && gmailConn.status === 'active' && gmailConn.encryptedRefreshToken) {
    try {
      const { sendViaConnectedGmail } = require('./gmail-api');
      const clientId = process.env.GOOGLE_CLIENT_ID || '';
      const clientSecret = process.env.GOOGLE_CLIENT_SECRET || '';
      const result = await sendViaConnectedGmail({
        db,
        uid,
        encryptionKey: key,
        clientId,
        clientSecret,
        emailOptions: {
          to: job.message.to,
          cc: job.message.cc,
          bcc: job.message.bcc,
          replyTo: job.message.replyTo,
          subject: job.message.subject,
          text: job.message.text,
          html: job.message.html,
          attachments: job.message.attachments,
          fromName: job.message.fromName || 'Mail India'
        }
      });
      await transition(db, uid, id, ['processing'], 'accepted', {
        provider: 'gmail_api',
        senderEmail: result.connectedEmail,
        providerMessageId: String(result.messageId || '').slice(0, 200)
      });
      return;
    } catch (gmailErr) {
      console.warn(`[GMAIL API DISPATCH EXCEPTION, ATTEMPTING POOL FALLBACK] uid: ${uid}`, gmailErr.message);
      if (gmailErr.code === 'GMAIL_TOKEN_REVOKED') {
        await db.ref(`gmail_connections/${uid}/status`).set('needs_reconnect').catch(() => {});
      }
    }
  }

  let senderId=job.senderId;
  if(!safeId(senderId)){await transition(db,uid,id,['processing'],'failed',{error:'SENDER_UNAVAILABLE'});return}
  if(assignment?.manual && assignment?.senderId && assignment.senderId!==senderId){await transition(db,uid,id,['processing'],'failed',{error:'SENDER_UNAVAILABLE'});return}
  let sender=(await db.ref('sender_accounts/'+senderId).get()).val();
  if(!sender||sender.status!=='active'){
    if (isPinnedSender) { await transition(db,uid,id,['processing'],'failed',{error:'SENDER_UNAVAILABLE'}); return; }
    const sendersSnap = await db.ref('sender_accounts').get();
    const active = Object.entries(sendersSnap.val() || {}).find(([_, s]) => s && s.status === 'active');
    if (active) {
      senderId = active[0];
      sender = active[1];
    } else {
      await transition(db,uid,id,['processing'],'failed',{error:'SENDER_UNAVAILABLE'});
      return;
    }
  }
  let secret;try{secret=decryptCredentials(key,senderId,sender.credentials)}catch{await transition(db,uid,id,['processing'],'failed',{error:'SENDER_CONFIGURATION_ERROR'});return}
  let day=new Date().toISOString().slice(0,10);
  if(!await senderAttempt(db,senderId,day)){await transition(db,uid,id,['processing'],'failed',{error:'SENDER_QUOTA_EXCEEDED'});return}
  const m=job.message;
  try{
    // Any error after entering sendMail is treated as uncertain. SMTP can lose the final
    // response after server acceptance, so automatic retries or refunds would be unsafe.
    const fromAddress = sender.name ? `"${sender.name.replace(/["\r\n]/g, '')}" <${sender.email}>` : `"Mail India" <${sender.email}>`;
    let info=await send(sender,{from:fromAddress,to:m.to,subject:m.subject,...(m.text?{text:m.text}:{}),...(m.html?{html:m.html}:{}),messageId:`<mb.${id}@mailbridge.local>`},secret);
    if(!Array.isArray(info.accepted)||!info.accepted.length){
      await transition(db,uid,id,['processing'],'unknown',{error:'PROVIDER_OUTCOME_UNCERTAIN'});
      return;
    }
    await transition(db,uid,id,['processing'],'accepted',{senderId,providerMessageId:String(info.messageId||'').slice(0,200)});
  }catch(e){
    // If SMTP returns an explicit 5xx permanent rejection code, record bounce (exclude sender authentication failures)
    const isAuthError = e.code === 'EAUTH' || Number(e.responseCode) === 535 || Number(e.responseCode) === 534 || /auth|invalid login/i.test(e.message || '');
    if(!isAuthError && Number(e.responseCode)>=500&&Number(e.responseCode)<600){
      try{
        const {recordBounce}=require('./bounces');
        await recordBounce(db,{recipient:m.to,type:'hard',reason:e.message||'SMTP 5xx rejection',messageId:id,source:'smtp_error'});
      }catch(err){console.error('Bounce recording error:',err.message);}
    }
    await transition(db,uid,id,['processing'],'unknown',{error:'PROVIDER_OUTCOME_UNCERTAIN'});
    await db.ref('sender_accounts/'+senderId+'/status').set('paused');
  }
}

module.exports={encryptCredentials,decryptCredentials,transport,normalize,validEmail,safeId,reserve,transition,runJob,sha};
