'use strict';
const crypto = require('node:crypto');
const { projectLog } = require('./logs');

const DEFAULT_STUCK_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Scans for stuck jobs in wallets across the database.
 */
async function scanQueueState(db, timeoutMs = DEFAULT_STUCK_TIMEOUT_MS) {
  const [walletsSnap, dlqSnap] = await Promise.all([
    db.ref('wallets').get(),
    db.ref('queue_dlq').get()
  ]);

  const now = Date.now();
  const stuckProcessing = [];
  const stuckQueued = [];
  const unknownJobs = [];
  const deadLetterJobs = [];

  const wallets = walletsSnap.val() || {};
  for (const [uid, wallet] of Object.entries(wallets)) {
    if (!wallet || !wallet.sendRequests) continue;
    for (const [jobId, job] of Object.entries(wallet.sendRequests)) {
      if (!job) continue;
      const age = now - (job.updatedAt || job.createdAt || now);

      if (job.status === 'processing' && age > timeoutMs) {
        stuckProcessing.push({
          uid,
          id: jobId,
          status: 'processing',
          ageMs: age,
          createdAt: job.createdAt,
          updatedAt: job.updatedAt,
          senderId: job.senderId,
          recipient: job.message?.to
        });
      } else if (job.status === 'queued' && age > timeoutMs) {
        stuckQueued.push({
          uid,
          id: jobId,
          status: 'queued',
          ageMs: age,
          createdAt: job.createdAt,
          senderId: job.senderId,
          recipient: job.message?.to
        });
      } else if (job.status === 'unknown') {
        unknownJobs.push({
          uid,
          id: jobId,
          status: 'unknown',
          createdAt: job.createdAt,
          updatedAt: job.updatedAt,
          error: job.error,
          senderId: job.senderId,
          recipient: job.message?.to
        });
      }
    }
  }

  const dlq = dlqSnap.val() || {};
  for (const [id, item] of Object.entries(dlq)) {
    if (item) deadLetterJobs.push({ id, ...item });
  }

  return {
    stuckProcessing,
    stuckQueued,
    unknownJobs,
    deadLetterJobs,
    summary: {
      stuckProcessingCount: stuckProcessing.length,
      stuckQueuedCount: stuckQueued.length,
      unknownCount: unknownJobs.length,
      dlqCount: deadLetterJobs.length,
      scannedAt: now
    }
  };
}

/**
 * Recovers stuck jobs safely according to strict delivery safety rules:
 * - Stuck processing jobs: cannot be verified if Gmail accepted them; transition to UNKNOWN!
 * - Stuck queued jobs: never started SMTP, so safe to retry or cancel & release credit.
 */
async function autoRecoverStuckJobs(db, timeoutMs = DEFAULT_STUCK_TIMEOUT_MS) {
  const { stuckProcessing } = await scanQueueState(db, timeoutMs);
  const transitioned = [];

  for (const job of stuckProcessing) {
    const { uid, id } = job;
    const now = Date.now();

    // Move stuck processing job to 'unknown' to avoid indefinite lock and ambiguity
    const result = await db.ref('wallets/' + uid).transaction(w => {
      if (w === null) return null;
      const j = w?.sendRequests?.[id];
      if (!j || j.status !== 'processing') return;
      j.status = 'unknown';
      j.error = 'PROCESSING_TIMEOUT_LOCK_EXPIRED';
      j.updatedAt = now;
      return w;
    }, undefined, false);

    if (result.committed) {
      const updatedJob = result.snapshot.val().sendRequests[id];
      await projectLog(db, uid, updatedJob);
      transitioned.push({ uid, id, from: 'processing', to: 'unknown' });
    }
  }

  return { recoveredCount: transitioned.length, transitioned };
}

/**
 * Move a repeatedly failed job to the Dead-Letter Queue (DLQ).
 */
async function moveToDLQ(db, { uid, id, error, details, adminId }) {
  const now = Date.now();
  const jobSnap = await db.ref(`wallets/${uid}/sendRequests/${id}`).get();
  const job = jobSnap.val();
  if (!job) throw new Error('JOB_NOT_FOUND');

  const dlqEntry = {
    id,
    uid,
    job,
    error: error || 'MOVED_TO_DLQ',
    details: details || 'Manual or automatic DLQ transfer',
    movedBy: adminId || 'system',
    createdAt: now
  };

  // Add to DLQ and update status
  await db.ref('queue_dlq/' + id).set(dlqEntry);

  await db.ref('wallets/' + uid).transaction(w => {
    if (w === null) return null;
    const j = w?.sendRequests?.[id];
    if (!j) return;
    j.status = 'dead_letter';
    j.updatedAt = now;
    j.error = 'MOVED_TO_DLQ';
    return w;
  }, undefined, false);

  await projectLog(db, uid, { ...job, status: 'dead_letter', error: 'MOVED_TO_DLQ', updatedAt: now });

  return dlqEntry;
}

/**
 * Manual admin recovery action for stuck, unknown, or dead-letter jobs.
 */
async function manualRecoverJob({ db, sendQueue, uid, id, action, outcome, evidence, adminId }) {
  const now = Date.now();
  const jobSnap = await db.ref(`wallets/${uid}/sendRequests/${id}`).get();
  const job = jobSnap.val();
  if (!job) throw new Error('JOB_NOT_FOUND');

  if (action === 'retry_queued') {
    // Only safe to retry if it is currently 'queued' or 'dead_letter' (where SMTP definitely did not run)
    if (job.status !== 'queued' && job.status !== 'dead_letter') {
      throw new Error('CANNOT_RETRY_PROCESSING_OR_UNKNOWN_JOB');
    }
    if (!sendQueue) throw new Error('QUEUE_UNAVAILABLE');

    // Re-enqueue
    const sha = s => crypto.createHash('sha256').update(s).digest('hex');
    await sendQueue.add('send', { uid, id }, {
      jobId: sha(uid) + '-' + id + '-' + now,
      attempts: 1,
      removeOnComplete: false,
      removeOnFail: false
    });

    await db.ref(`wallets/${uid}/sendRequests/${id}`).update({
      status: 'queued',
      updatedAt: now,
      error: null
    });

    return { success: true, action: 're-enqueued', id };
  } else if (action === 'release_presend') {
    // Release credit for a job confirmed never sent
    if (job.status === 'accepted') {
      throw new Error('CANNOT_RELEASE_ACCEPTED_JOB');
    }

    let released = false;
    await db.ref('wallets/' + uid).transaction(w => {
      if (w === null) return null;
      const j = w?.sendRequests?.[id];
      if (!j) return;
      if (j.status === 'failed') return w; // already released

      if (Number.isSafeInteger(w.reserved) && w.reserved > 0) {
        w.reserved--;
        w.balance = (w.balance || 0) + 1;
        w.ledger = w.ledger || {};
        w.ledger['admin_release_' + id] = {
          type: 'admin_release',
          credits: 1,
          reference: id,
          adminId,
          createdAt: now
        };
      }
      j.status = 'failed';
      j.error = 'ADMIN_CANCELED_AND_RELEASED';
      j.updatedAt = now;
      released = true;
      return w;
    }, undefined, false);

    await projectLog(db, uid, { ...job, status: 'failed', error: 'ADMIN_CANCELED_AND_RELEASED', updatedAt: now });
    return { success: true, action: 'released', id };
  } else if (action === 'reconcile_outcome') {
    // Administrative reconciliation of uncertain outcome with proof
    if (job.status !== 'unknown') {
      throw new Error('ONLY_UNKNOWN_OUTCOMES_CAN_BE_RECONCILED');
    }
    if (!['accepted', 'failed'].includes(outcome)) {
      throw new Error('OUTCOME_MUST_BE_ACCEPTED_OR_FAILED');
    }
    if (!evidence || evidence.trim().length < 15) {
      throw new Error('PROVIDER_EVIDENCE_REQUIRED_AT_LEAST_15_CHARS');
    }

    let changed = false;
    await db.ref('wallets/' + uid).transaction(w => {
      if (w === null) return null;
      const j = w?.sendRequests?.[id];
      if (!j || j.status !== 'unknown' || !Number.isSafeInteger(w.reserved) || w.reserved < 1) return;

      w.reserved--;
      w.ledger = w.ledger || {};
      if (outcome === 'accepted') {
        w.consumed = (w.consumed || 0) + 1;
      } else {
        w.balance = (w.balance || 0) + 1;
      }
      j.status = outcome;
      j.updatedAt = now;
      j.error = null;
      j.reconciled = true;
      w.ledger['reconcile_' + id] = {
        type: 'manual_reconciliation',
        outcome,
        reference: id,
        adminId,
        evidence: evidence.trim(),
        createdAt: now
      };
      changed = true;
      return w;
    }, undefined, false);

    if (!changed) throw new Error('RECONCILIATION_TRANSACTION_FAILED');

    await projectLog(db, uid, { ...job, status: outcome, error: null, updatedAt: now });

    await db.ref('admin_logs/' + crypto.randomUUID()).set({
      adminId,
      action: 'queue.reconciled_outcome',
      target: id,
      details: { outcome, evidence: evidence.trim() },
      createdAt: now
    });

    return { success: true, action: 'outcome_reconciled', status: outcome, id };
  } else {
    throw new Error('INVALID_RECOVERY_ACTION');
  }
}

module.exports = {
  DEFAULT_STUCK_TIMEOUT_MS,
  scanQueueState,
  autoRecoverStuckJobs,
  moveToDLQ,
  manualRecoverJob
};
