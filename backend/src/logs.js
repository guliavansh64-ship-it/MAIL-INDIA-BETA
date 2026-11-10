'use strict';
// Minimal projection. The wallet's idempotency state remains authoritative.
// The expiration filter hides expired entries; a separate purge is required for deletion.
const RETENTION_MS=90*86400000;
async function projectLog(db,uid,job){if(!job||!job.id)return;let m=job.message||{};await db.ref(`email_logs/${uid}/${job.id}`).set({id:job.id,recipient:m.to||'',subject:m.subject||'',status:job.status,createdAt:job.createdAt,updatedAt:job.updatedAt||job.createdAt,error:job.error||null,expiresAt:job.createdAt+RETENTION_MS});}
function visibleLogs(value,now=Date.now()){return Object.values(value||{}).filter(x=>x&&Number.isFinite(x.createdAt)&&x.createdAt+RETENTION_MS>now).sort((a,b)=>b.createdAt-a.createdAt)}
module.exports={projectLog,visibleLogs,RETENTION_MS};
