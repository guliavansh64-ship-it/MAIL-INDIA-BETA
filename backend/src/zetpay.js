'use strict';
const express = require('express');

const DEFAULT_BASE_URL = 'https://zetpay-beta.vercel.app';

/**
 * ZetPay ZetAPI Provider Client
 * @param {string} apiKey 32-character ZetAPI key (zap_api)
 * @param {string} [baseUrl] Base URL for ZetPay API
 */
function zetpayProvider(apiKey, baseUrl = DEFAULT_BASE_URL) {
  if (!apiKey || typeof apiKey !== 'string') {
    throw new Error('ZetPay API key is required');
  }

  async function request(path, options = {}) {
    const url = (baseUrl || DEFAULT_BASE_URL) + path;
    const headers = {
      'Content-Type': 'application/json',
      'X-ZetAPI-Key': apiKey,
      ...(options.headers || {})
    };

    const res = await fetch(url, {
      ...options,
      headers,
      signal: AbortSignal.timeout(15000)
    });

    let data;
    try {
      data = await res.json();
    } catch {
      throw new Error(`ZETPAY_HTTP_${res.status}`);
    }

    if (!res.ok || data.success === false) {
      throw new Error(data.message || `ZETPAY_HTTP_${res.status}`);
    }
    return data;
  }

  return {
    apiKey,
    baseUrl: baseUrl || DEFAULT_BASE_URL,

    /**
     * Creates a new ZetPay payment order
     * @param {Object} params
     * @param {number} params.amount Clean number from Rs.1 to Rs.5,000
     * @param {string} [params.title] Title (max 100 chars)
     * @param {string} [params.customerMobile] 10-digit mobile number
     * @param {string} [params.redirectUrl] Return URL after payment
     * @param {boolean} [params.useEmbedded] Set true for widget / popup flow
     */
    async createOrder({ amount, title = 'Mail India Credits', customerMobile, redirectUrl, useEmbedded = true }) {
      const cleanAmount = Number(String(amount).replace(/[^0-9.]/g, ''));
      if (!Number.isFinite(cleanAmount) || cleanAmount < 1 || cleanAmount > 5000) {
        throw new Error('Amount must be between ₹1 and ₹5,000');
      }

      const body = {
        zap_api: apiKey,
        amount: cleanAmount,
        title: String(title || 'ZetPay Payment').slice(0, 100),
        useEmbedded: Boolean(useEmbedded)
      };

      if (customerMobile) {
        const cleanMobile = String(customerMobile).replace(/[^0-9]/g, '');
        if (cleanMobile.length >= 10) {
          body.customer_mobile = cleanMobile.slice(-10);
        }
      }

      if (redirectUrl) {
        body.redirect_url = redirectUrl;
      }

      const res = await request('/api/developer/create-order', {
        method: 'POST',
        body: JSON.stringify(body)
      });

      return res.data; // { order_id, payment_url, amount, mode }
    },

    /**
     * Fetches order status server-to-server
     * Status is always one of: "pending" | "success" | "failed"
     * @param {string} orderId The order_id returned from createOrder
     */
    async getOrderStatus(orderId) {
      if (!orderId || typeof orderId !== 'string') {
        throw new Error('Order ID is required');
      }

      const res = await request('/api/developer/order-status/' + encodeURIComponent(orderId), {
        method: 'GET'
      });

      return res.data; // { order_id, status: "pending"|"success"|"failed", amount }
    }
  };
}

/**
 * Creates Express routes for ZetPay integration
 */
function createZetpayRoutes({ db, authenticate, ensureActive, provider, distributedLimiter }) {
  const router = express.Router();

  // Helper to commit credits into user's wallet transactionally and idempotently
  async function applyZetpayPayment(orderId, verifiedOrder) {
    const orderRef = db.ref('payment_orders/' + orderId);
    const order = (await orderRef.get()).val();
    if (!order) throw new Error('ORDER_NOT_FOUND');
    if (order.status === 'captured') {
      return { orderId, alreadyCredited: true, credits: order.credits };
    }

    const now = Date.now();
    const result = await db.ref('wallets/' + order.uid).transaction(wallet => {
      wallet = wallet || { balance: 0, reserved: 0, purchased: 0, consumed: 0 };
      for (const k of ['balance', 'reserved', 'purchased', 'consumed']) {
        if (!Number.isSafeInteger(wallet[k] ?? 0) || (wallet[k] ?? 0) < 0) return;
      }
      wallet.paymentOrders = wallet.paymentOrders || {};
      wallet.ledger = wallet.ledger || {};

      // Deduplication check
      if (wallet.paymentOrders[orderId]) return wallet;

      if (!Number.isSafeInteger(order.credits) || order.credits <= 0) return;

      wallet.balance = (wallet.balance || 0) + order.credits;
      wallet.purchased = (wallet.purchased || 0) + order.credits;
      wallet.paymentOrders[orderId] = orderId;
      wallet.ledger['purchase_' + orderId] = {
        type: 'purchase',
        provider: 'zetpay',
        credits: order.credits,
        amountRupees: order.amountRupees,
        amountPaise: order.amountPaise,
        reference: orderId,
        createdAt: now
      };
      return wallet;
    }, undefined, false);

    if (!result.committed) throw new Error('WALLET_TRANSACTION_FAILED');

    await orderRef.update({
      status: 'captured',
      paymentId: orderId,
      capturedAt: now
    });

    const notifId = 'notif_' + now + '_' + Math.random().toString(36).slice(2, 8);
    await db.ref(`notifications/${order.uid}/${notifId}`).set({
      id: notifId,
      uid: order.uid,
      title: `ZetPay UPI Recharge: +${order.credits} Credits`,
      message: `₹${order.amountRupees || ((order.amountPaise || 0) / 100)} recharge confirmed. Wallet credited with ${order.credits} credits.`,
      category: 'billing',
      type: 'success',
      link: '/wallet.html',
      read: false,
      readAt: null,
      createdAt: now
    }).catch(() => {});

    return { orderId, credited: true, credits: order.credits };
  }

  // 1. Create ZetPay Order
  router.post('/order', authenticate, ensureActive, async (req, res) => {
    // Distributed rate limit check
    if (distributedLimiter && typeof distributedLimiter.checkScoped === 'function') {
      const allowed = await distributedLimiter.checkScoped('payment', req.user.uid);
      if (!allowed) {
        return res.status(429).json({ error: 'RATE_LIMIT_EXCEEDED', message: 'Too many order requests. Please wait a moment.' });
      }
    }

    const rawAmount = req.body?.amount ?? req.body?.amountRupees;
    const amountRupees = Number(String(rawAmount).replace(/[^0-9.]/g, ''));

    if (!Number.isInteger(amountRupees) || amountRupees < 1 || amountRupees > 5000) {
      return res.status(400).json({
        error: 'INVALID_AMOUNT',
        message: 'Amount must be an integer between ₹1 and ₹5,000.'
      });
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
      rate = 10; // ₹0.10/email for Google users
    } else {
      try {
        const settings = (await db.ref('platform_settings').get()).val() || {};
        rate = settings.creditRate ?? 5;
      } catch {
        rate = 5;
      }
      if (!Number.isSafeInteger(rate) || rate < 1 || rate > 100) rate = 5;
    }

    const baseCredits = amountRupees * rate;
    let bonusCredits = 0;
    if (baseCredits >= 50000) bonusCredits = 15000;
    else if (baseCredits >= 25000) bonusCredits = 5000;
    else if (baseCredits >= 10000) bonusCredits = 1500;
    else if (baseCredits >= 5000) bonusCredits = 500; // Buy 5000 coin get 500 extra!
    else if (baseCredits >= 2000) bonusCredits = 150;

    const credits = baseCredits + bonusCredits;
    const amountPaise = amountRupees * 100;

    try {
      const title = req.body?.title || `Mail India — ${credits} Credits`;
      const order = await provider.createOrder({
        amount: amountRupees,
        title,
        customerMobile: req.body?.customerMobile,
        redirectUrl: req.body?.redirectUrl,
        useEmbedded: req.body?.useEmbedded !== false
      });

      const orderRecord = {
        provider: 'zetpay',
        uid: req.user.uid,
        orderId: order.order_id,
        amountRupees,
        amountPaise,
        baseCredits,
        bonusCredits,
        credits,
        creditRate: rate,
        isGoogleUser,
        status: 'created',
        paymentUrl: order.payment_url,
        mode: order.mode || 'live',
        createdAt: Date.now(),
        refundedPaise: 0
      };

      await db.ref('payment_orders/' + order.order_id).set(orderRecord);

      res.status(201).json({
        success: true,
        provider: 'zetpay',
        orderId: order.order_id,
        paymentUrl: order.payment_url,
        amount: amountRupees,
        baseCredits,
        bonusCredits,
        credits,
        creditRate: rate,
        isGoogleUser,
        mode: order.mode,
        apiKey: provider.apiKey
      });
    } catch (err) {
      console.error('ZetPay order creation failed:', err.message);
      res.status(502).json({
        error: 'ORDER_CREATION_FAILED',
        message: err.message || 'Could not create ZetPay payment order.'
      });
    }
  });

  // 2. Confirm / Verify Order (Server-to-Server Golden Rule)
  router.post('/verify', authenticate, ensureActive, async (req, res) => {
    const orderId = req.body?.orderId || req.body?.order_id;
    if (!orderId || typeof orderId !== 'string') {
      return res.status(400).json({ error: 'MISSING_ORDER_ID', message: 'Order ID is required.' });
    }

    try {
      const order = (await db.ref('payment_orders/' + orderId).get()).val();
      if (!order) {
        return res.status(404).json({ error: 'ORDER_NOT_FOUND', message: 'Order not found.' });
      }
      if (order.uid !== req.user.uid) {
        return res.status(403).json({ error: 'UNAUTHORIZED_ORDER', message: 'Not authorized for this order.' });
      }

      // If already captured, return immediately
      if (order.status === 'captured') {
        const wallet = (await db.ref('wallets/' + req.user.uid).get()).val() || {};
        return res.json({
          success: true,
          status: 'credited',
          alreadyCredited: true,
          credits: order.credits,
          balance: wallet.balance || 0
        });
      }

      // Query ZetPay status server-to-server
      const zetpayStatus = await provider.getOrderStatus(orderId);

      if (zetpayStatus.status === 'success') {
        // Confirm amount matches to prevent tampering
        if (Number(zetpayStatus.amount) !== Number(order.amountRupees)) {
          throw new Error('AMOUNT_MISMATCH');
        }

        // Apply credits transactionally
        await applyZetpayPayment(orderId, zetpayStatus);
        const wallet = (await db.ref('wallets/' + req.user.uid).get()).val() || {};

        return res.json({
          success: true,
          status: 'credited',
          credits: order.credits,
          balance: wallet.balance || 0,
          message: `Payment confirmed. ${order.credits} credits added to your wallet.`
        });
      } else if (zetpayStatus.status === 'pending') {
        return res.json({
          success: true,
          status: 'pending',
          message: 'Payment is still pending. Please complete UPI payment in the popup.'
        });
      } else {
        await db.ref('payment_orders/' + orderId).update({ status: 'failed' });
        return res.status(400).json({
          success: false,
          status: 'failed',
          message: 'Payment failed or cancelled.'
        });
      }
    } catch (err) {
      console.error('ZetPay verify error:', err.message);
      res.status(500).json({ error: 'VERIFICATION_ERROR', message: err.message });
    }
  });

  // 3. Status Poll Endpoint
  router.get('/status/:orderId', authenticate, ensureActive, async (req, res) => {
    const { orderId } = req.params;
    try {
      const order = (await db.ref('payment_orders/' + orderId).get()).val();
      if (!order || order.uid !== req.user.uid) {
        return res.status(404).json({ error: 'ORDER_NOT_FOUND' });
      }

      if (order.status === 'captured') {
        return res.json({ success: true, status: 'success', credited: true, credits: order.credits });
      }

      const zetpayStatus = await provider.getOrderStatus(orderId);
      if (zetpayStatus.status === 'success') {
        await applyZetpayPayment(orderId, zetpayStatus);
        return res.json({ success: true, status: 'success', credited: true, credits: order.credits });
      }

      res.json({ success: true, status: zetpayStatus.status, credited: false });
    } catch (err) {
      res.status(500).json({ error: 'STATUS_FETCH_FAILED', message: err.message });
    }
  });

  // 4. Auto-Sync all pending orders for the authenticated user
  router.all('/sync-pending', authenticate, ensureActive, async (req, res) => {
    try {
      const ordersSnap = await db.ref('payment_orders').get();
      const allOrders = ordersSnap.val() || {};
      const now = Date.now();
      const oneDayAgo = now - (24 * 60 * 60 * 1000);

      const userPendingOrders = Object.values(allOrders).filter(o =>
        o && o.uid === req.user.uid &&
        (o.status === 'created' || o.status === 'pending') &&
        (o.createdAt || 0) > oneDayAgo
      );

      let creditedCount = 0;
      let totalCreditsAdded = 0;

      for (const order of userPendingOrders) {
        try {
          const zetpayStatus = await provider.getOrderStatus(order.orderId);
          if (zetpayStatus && (zetpayStatus.status === 'success' || zetpayStatus.status === 'PAID' || zetpayStatus.status === 'COMPLETED')) {
            await applyZetpayPayment(order.orderId, zetpayStatus);
            creditedCount++;
            totalCreditsAdded += (order.credits || 0);
          } else if (zetpayStatus && (zetpayStatus.status === 'failed' || zetpayStatus.status === 'cancelled')) {
            await db.ref('payment_orders/' + order.orderId).update({ status: 'failed' });
          }
        } catch (itemErr) {
          console.warn(`[SYNC-PENDING CHECK FAIL] order: ${order.orderId}`, itemErr.message);
        }
      }

      const walletSnap = await db.ref('wallets/' + req.user.uid).get();
      const wallet = walletSnap.val() || {};

      res.json({
        success: true,
        creditedCount,
        totalCreditsAdded,
        wallet: {
          balance: wallet.balance || 0,
          purchased: wallet.purchased || 0,
          consumed: wallet.consumed || 0
        }
      });
    } catch (err) {
      console.error('[SYNC PENDING ERROR]', err);
      res.status(500).json({ success: false, error: 'SYNC_FAILED', message: err.message });
    }
  });

  // 5. Return Redirect Handler (when customer completes payment via browser redirect)
  router.get('/return', async (req, res) => {
    const orderId = req.query.zp_order;
    if (!orderId) {
      return res.redirect('/#wallet?error=missing_order');
    }

    try {
      const order = (await db.ref('payment_orders/' + orderId).get()).val();
      if (order) {
        const zetpayStatus = await provider.getOrderStatus(orderId);
        if (zetpayStatus.status === 'success' && order.status !== 'captured') {
          await applyZetpayPayment(orderId, zetpayStatus);
        }
      }
      res.redirect(`/#wallet?zp_order=${encodeURIComponent(orderId)}&status=success`);
    } catch {
      res.redirect(`/#wallet?zp_order=${encodeURIComponent(orderId)}&status=check`);
    }
  });

  return { router, applyZetpayPayment };
}

module.exports = {
  DEFAULT_BASE_URL,
  zetpayProvider,
  createZetpayRoutes
};
