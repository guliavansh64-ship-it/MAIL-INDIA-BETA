'use strict';
const crypto = require('node:crypto');
const express = require('express');
const { handleRefundWebhook } = require('./refunds');
const { handleDisputeWebhook } = require('./disputes');

function validSignature(secret, payload, sig) {
  if (!secret || typeof sig !== 'string' || !/^[a-f0-9]{64}$/i.test(sig)) return false;
  const expected = crypto.createHmac('sha256', secret).update(payload).digest();
  const supplied = Buffer.from(sig, 'hex');
  return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
}

function createPaymentRoutes({ db, authenticate, ensureActive, config, provider, distributedLimiter }) {
  const router = express.Router();
  const enabled = () => config.enabled && typeof config.keyId === 'string' && config.keyId.startsWith('rzp_test_') && config.keySecret && config.webhookSecret;

  // Financial state is committed in one RTDB transaction under the wallet, including
  // the order dedupe marker and ledger entry. The amount and rate are immutable snapshots.
  async function applyCapturedPayment(orderId, paymentId) {
    const order = (await db.ref('payment_orders/' + orderId).get()).val();
    if (!order) throw new Error('ORDER_NOT_FOUND');
    const payment = await provider.getPayment(paymentId);
    if (payment.id !== paymentId || payment.order_id !== orderId || payment.status !== 'captured' || (payment.amount_refunded || 0) !== 0 || payment.currency !== 'INR' || payment.amount !== order.amountPaise) {
      throw new Error('PAYMENT_MISMATCH');
    }
    const now = Date.now();
    const result = await db.ref('wallets/' + order.uid).transaction(wallet => {
      wallet = wallet || { balance: 0, reserved: 0, purchased: 0, consumed: 0 };
      for (const k of ['balance', 'reserved', 'purchased', 'consumed']) {
        if (!Number.isSafeInteger(wallet[k] ?? 0) || (wallet[k] ?? 0) < 0) return;
      }
      wallet.paymentOrders = wallet.paymentOrders || {};
      wallet.ledger = wallet.ledger || {};
      if (wallet.paymentOrders[orderId]) return wallet;
      if (!Number.isSafeInteger(order.credits) || order.credits <= 0 || !Number.isSafeInteger((wallet.balance || 0) + order.credits) || !Number.isSafeInteger((wallet.purchased || 0) + order.credits)) return;
      wallet.balance = (wallet.balance || 0) + order.credits;
      wallet.purchased = (wallet.purchased || 0) + order.credits;
      wallet.paymentOrders[orderId] = paymentId;
      wallet.ledger['purchase_' + orderId] = { type: 'purchase', credits: order.credits, amountPaise: order.amountPaise, reference: paymentId, createdAt: now };
      return wallet;
    }, undefined, false);

    if (!result.committed) throw new Error('WALLET_TRANSACTION_FAILED');
    const persisted = result.snapshot.val();
    if (persisted.paymentOrders[orderId] !== paymentId) throw new Error('ORDER_ALREADY_CREDITED');
    await db.ref('payment_orders/' + orderId).update({ status: 'captured', paymentId, capturedAt: now });
    const notifId = 'notif_' + now + '_' + Math.random().toString(36).slice(2, 8);
    await db.ref(`notifications/${order.uid}/${notifId}`).set({
      id: notifId,
      uid: order.uid,
      title: `Payment Received: +${order.credits} Credits`,
      message: `₹${((order.amountPaise || 0) / 100).toFixed(2)} recharge confirmed. Your wallet balance has been updated.`,
      category: 'billing',
      type: 'success',
      link: '/wallet.html',
      read: false,
      readAt: null,
      createdAt: now
    }).catch(() => {});
    return { orderId, paymentId };
  }

  router.post('/webhook', express.raw({ type: 'application/json', limit: '64kb' }), async (req, res) => {
    if (!enabled()) return res.status(503).json({ error: 'PAYMENTS_DISABLED' });
    if (!Buffer.isBuffer(req.body) || !validSignature(config.webhookSecret, req.body, req.get('x-razorpay-signature'))) {
      return res.status(401).json({ error: 'INVALID_SIGNATURE' });
    }

    let event;
    try {
      event = JSON.parse(req.body.toString('utf8'));
    } catch {
      return res.status(400).json({ error: 'INVALID_JSON' });
    }

    const eventId = req.get('x-razorpay-event-id') || crypto.createHash('sha256').update(req.body).digest('hex');

    // Webhook Idempotency Check
    const eventRef = db.ref('processed_webhook_events/' + eventId);
    const existingSnap = await eventRef.get();
    if (existingSnap.val()) {
      return res.json({ received: true, duplicate: true });
    }

    // Handle Refund Webhook Events
    if (typeof event.event === 'string' && /^refund\./.test(event.event)) {
      try {
        await eventRef.set({ event: event.event, receivedAt: Date.now() });
        const result = await handleRefundWebhook({ db, event, eventId });
        return res.json({ received: true, refund: result });
      } catch (err) {
        console.error('Refund webhook processing error:', err.message);
        return res.status(503).json({ error: 'REFUND_PROCESSING_FAILED', message: err.message });
      }
    }

    // Handle Dispute / Chargeback Webhook Events
    if (typeof event.event === 'string' && (/^payment\.dispute\./.test(event.event) || /^dispute\./.test(event.event))) {
      try {
        await eventRef.set({ event: event.event, receivedAt: Date.now() });
        const result = await handleDisputeWebhook({ db, event, eventId });
        return res.json({ received: true, dispute: result });
      } catch (err) {
        console.error('Dispute webhook processing error:', err.message);
        return res.status(503).json({ error: 'DISPUTE_PROCESSING_FAILED', message: err.message });
      }
    }

    // Handle Payment Captured
    if (event.event === 'payment.captured') {
      const p = event.payload?.payment?.entity;
      if (!p || !/^order_[A-Za-z0-9]+$/.test(p.order_id || '') || !/^pay_[A-Za-z0-9]+$/.test(p.id || '')) {
        return res.status(400).json({ error: 'INVALID_EVENT' });
      }
      try {
        await applyCapturedPayment(p.order_id, p.id);
        await eventRef.set({ event: event.event, orderId: p.order_id, paymentId: p.id, receivedAt: Date.now() });
        return res.json({ received: true });
      } catch (e) {
        console.error('Payment webhook rejected:', e.message);
        return res.status(503).json({ error: 'PROCESSING_FAILED' });
      }
    }

    return res.status(200).json({ received: true, ignored: true });
  });

  router.post('/orders', authenticate, ensureActive, async (req, res) => {
    if (!enabled()) return res.status(503).json({ error: 'PAYMENTS_DISABLED', message: 'Payment integration is disabled.' });
    if (!req.user.email_verified) return res.status(403).json({ error: 'EMAIL_NOT_VERIFIED' });

    // Rate limiting for order creation
    if (distributedLimiter && typeof distributedLimiter.checkScoped === 'function') {
      const allowed = await distributedLimiter.checkScoped('payment', req.user.uid);
      if (!allowed) {
        return res.status(429).json({ error: 'RATE_LIMIT_EXCEEDED', message: 'Too many order requests. Please wait a moment.' });
      }
    }

    const amountPaise = req.body?.amountPaise;
    if (!Number.isSafeInteger(amountPaise) || amountPaise < 1000 || amountPaise > 100000 || amountPaise % 100 !== 0) {
      return res.status(400).json({ error: 'INVALID_AMOUNT', message: 'Amount must be a whole rupee between ₹10 and ₹1,000.' });
    }

    let rate = 5;
    let isGoogleUser = false;
    try {
      const uSnap = await db.ref(`users/${req.user.uid}`).get();
      const u = uSnap.val() || {};
      const gSnap = await db.ref(`gmail_connections/${req.user.uid}`).get();
      const g = gSnap.val();
      isGoogleUser = Boolean(
        req.user?.authProvider === 'google' ||
        u.authProvider === 'google' ||
        u.googleId ||
        (g && g.status === 'active') ||
        (req.user?.email && req.user.email.toLowerCase().endsWith('@gmail.com'))
      );
    } catch {}

    if (isGoogleUser) {
      rate = 10;
    } else {
      try {
        const settings = (await db.ref('platform_settings').get()).val() || {};
        rate = settings.creditRate ?? 5;
      } catch {
        return res.status(503).json({ error: 'SETTINGS_UNAVAILABLE' });
      }
      if (!Number.isSafeInteger(rate) || rate < 1 || rate > 100) return res.status(503).json({ error: 'INVALID_SETTINGS' });
    }

    const amountRupees = amountPaise / 100;
    const baseCredits = amountRupees * rate;
    let bonusCredits = 0;
    if (baseCredits >= 50000) bonusCredits = 15000;
    else if (baseCredits >= 25000) bonusCredits = 5000;
    else if (baseCredits >= 10000) bonusCredits = 1500;
    else if (baseCredits >= 5000) bonusCredits = 500;
    else if (baseCredits >= 2000) bonusCredits = 150;

    const credits = baseCredits + bonusCredits;
    try {
      const receipt = 'mb_' + crypto.randomBytes(12).toString('hex');
      const order = await provider.createOrder({ amount: amountPaise, currency: 'INR', receipt });
      if (!/^order_[A-Za-z0-9]+$/.test(order.id || '') || order.amount !== amountPaise || order.currency !== 'INR') {
        throw Error('ORDER_MISMATCH');
      }
      await db.ref('payment_orders/' + order.id).set({
        uid: req.user.uid,
        amountPaise,
        baseCredits,
        bonusCredits,
        credits,
        creditRate: rate,
        isGoogleUser,
        status: 'created',
        createdAt: Date.now(),
        receipt,
        refundedPaise: 0
      });
      res.status(201).json({ success: true, orderId: order.id, amountPaise, currency: 'INR', credits, baseCredits, bonusCredits, creditRate: rate, isGoogleUser, keyId: config.keyId });
    } catch (e) {
      console.error('Payment order creation failed:', e.message);
      res.status(502).json({ error: 'ORDER_CREATION_FAILED', message: 'Could not create an order. Please try again.' });
    }
  });

  router.post('/verify', authenticate, ensureActive, async (req, res) => {
    if (!enabled()) return res.status(503).json({ error: 'PAYMENTS_DISABLED' });
    const { razorpay_order_id: o, razorpay_payment_id: p, razorpay_signature: s } = req.body || {};
    if (!/^order_[A-Za-z0-9]+$/.test(o || '') || !/^pay_[A-Za-z0-9]+$/.test(p || '') || !validSignature(config.keySecret, o + '|' + p, s)) {
      return res.status(400).json({ error: 'INVALID_SIGNATURE' });
    }
    try {
      const order = (await db.ref('payment_orders/' + o).get()).val();
      if (!order || order.uid !== req.user.uid) return res.status(404).json({ error: 'ORDER_NOT_FOUND' });
      res.json({ success: true, status: order.status === 'captured' ? 'credited' : 'awaiting_webhook' });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  router.get('/history', authenticate, ensureActive, async (req, res) => {
    try {
      const wallet = (await db.ref('wallets/' + req.user.uid).get()).val() || {};
      let entries = Object.entries(wallet.ledger || {}).map(([id, v]) => ({ id, ...v })).sort((a, b) => b.createdAt - a.createdAt);
      res.json({ success: true, transactions: entries.slice(0, 100) });
    } catch {
      return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
    }
  });

  router.get('/orders', authenticate, ensureActive, async (req, res) => {
    try {
      const [ordersSnap, walletSnap] = await Promise.all([
        db.ref('payment_orders').get(),
        db.ref('wallets/' + req.user.uid).get()
      ]);
      const orders = ordersSnap.val() || {};
      const wallet = walletSnap.val() || {};

      const userOrders = Object.entries(orders)
        .map(([id, o]) => ({ id, ...o }))
        .filter(o => o.uid === req.user.uid);

      const ledgerPurchases = Object.entries(wallet.ledger || {})
        .filter(([, v]) => v && v.type === 'purchase')
        .map(([k, v]) => ({
          id: v.reference || k,
          uid: req.user.uid,
          amountRupees: v.amountRupees || (v.amountPaise ? v.amountPaise / 100 : (v.credits ? v.credits / 5 : 0)),
          amountPaise: v.amountPaise || (v.amountRupees ? v.amountRupees * 100 : (v.credits ? v.credits * 20 : 0)),
          credits: v.credits || 0,
          provider: v.provider || 'zetpay',
          status: 'captured',
          createdAt: v.createdAt || Date.now()
        }));

      const orderMap = new Map();
      for (const o of userOrders) {
        orderMap.set(o.id, o);
      }
      for (const p of ledgerPurchases) {
        if (!orderMap.has(p.id)) {
          orderMap.set(p.id, p);
        } else {
          const existing = orderMap.get(p.id);
          orderMap.set(p.id, { ...p, ...existing, status: existing.status || 'captured' });
        }
      }

      const list = Array.from(orderMap.values()).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
      res.json({ success: true, orders: list });
    } catch (err) {
      res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    }
  });

  return { router, applyCapturedPayment };
}

function razorpayProvider(keyId, keySecret) {
  async function request(path, options = {}) {
    const r = await fetch('https://api.razorpay.com/v1' + path, {
      ...options,
      headers: {
        Authorization: 'Basic ' + Buffer.from(keyId + ':' + keySecret).toString('base64'),
        'Content-Type': 'application/json'
      },
      signal: AbortSignal.timeout(15000)
    });
    if (!r.ok) throw Error('RAZORPAY_HTTP_' + r.status);
    return r.json();
  }
  return {
    createOrder: data => request('/orders', { method: 'POST', body: JSON.stringify(data) }),
    getPayment: id => request('/payments/' + encodeURIComponent(id)),
    createRefund: (paymentId, data) => request('/payments/' + encodeURIComponent(paymentId) + '/refund', { method: 'POST', body: JSON.stringify(data) }),
    getRefund: id => request('/refunds/' + encodeURIComponent(id))
  };
}

module.exports = { validSignature, createPaymentRoutes, razorpayProvider };
