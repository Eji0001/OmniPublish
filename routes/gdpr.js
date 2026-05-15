'use strict';

const express = require('express');
const { supabase } = require('../config/database');
const { verifyToken } = require('../middleware/auth');
const { gdprExportRateLimiter, gdprMutationRateLimiter, gdprStatusRateLimiter } = require('../middleware/rateLimit');
const { logger } = require('../utils/logger');

const router = express.Router();
router.use(verifyToken);
const getDb = (req) => req.db || supabase;

router.post('/export-data', gdprExportRateLimiter, async (req, res) => {
  const userId = req.user.id;
  const db = getDb(req);

  try {
    const exportData = {};
    const userColumns = 'id, email, full_name, avatar_url, role, plan, is_verified, is_active, user_type, onboarding_completed_at, last_login_at, marketing_consent, marketing_consent_at, timezone, created_at, updated_at';

    const { data: user } = await db.from('users').select(userColumns).eq('id', userId).single();
    exportData.user = user ? { ...user, password_hash: undefined } : null;

    const { data: posts } = await db.from('posts').select('*');
    exportData.posts = posts || [];

    const { data: connections } = await db.from('platform_connections')
      .select('id, platform, platform_user_id, platform_username, is_active, connected_at');
    exportData.platform_connections = connections || [];

    const { data: media } = await db.from('media_files').select('*');
    exportData.media_files = media || [];

    const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();
    const { data: activities } = await db.from('audit_logs')
      .select('*').eq('user_id', userId).gte('created_at', ninetyDaysAgo).limit(1000);
    exportData.activity_logs = activities || [];

    logger.info('User data exported', { userId, dataSize: JSON.stringify(exportData).length });

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="omnipublish-export-${userId}.json"`);
    res.json({ exported_at: new Date().toISOString(), user_id: userId, data: exportData });
  } catch (err) {
    logger.error('Data export failed', { userId, err: err.message });
    res.status(500).json({ error: 'Failed to export data', code: 'EXPORT_FAILED' });
  }
});

router.post('/request-deletion', gdprMutationRateLimiter, async (req, res) => {
  const userId = req.user.id;
  const deletionScheduledFor = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
  const db = getDb(req);

  try {
    const { error } = await db.from('users')
      .update({ deletion_requested_at: new Date(), deletion_scheduled_for: deletionScheduledFor })
      .eq('id', userId);
    if (error) throw error;

    logger.info('Account deletion requested', { userId, scheduledFor: deletionScheduledFor });
    res.json({
      message: 'Account deletion scheduled',
      deletion_scheduled_for: deletionScheduledFor,
      grace_period_days: 30,
      note: 'You can cancel this request within 30 days by contacting support',
    });
  } catch (err) {
    logger.error('Deletion request failed', { userId, err: err.message });
    res.status(500).json({ error: 'Failed to schedule deletion', code: 'DELETION_REQUEST_FAILED' });
  }
});

router.post('/cancel-deletion', gdprMutationRateLimiter, async (req, res) => {
  const userId = req.user.id;
  const db = getDb(req);

  try {
    const { error } = await db.from('users')
      .update({ deletion_requested_at: null, deletion_scheduled_for: null })
      .eq('id', userId);
    if (error) throw error;

    logger.info('Account deletion cancelled', { userId });
    res.json({ message: 'Account deletion cancelled' });
  } catch (err) {
    logger.error('Deletion cancellation failed', { userId, err: err.message });
    res.status(500).json({ error: 'Failed to cancel deletion', code: 'CANCELLATION_FAILED' });
  }
});

router.get('/status', gdprStatusRateLimiter, async (req, res) => {
  const userId = req.user.id;
  const db = getDb(req);

  try {
    const { data: user } = await db.from('users')
      .select('deletion_requested_at, deletion_scheduled_for, created_at, marketing_consent')
      .eq('id', userId).single();

    res.json({
      account_created: user?.created_at,
      deletion_pending: !!user?.deletion_requested_at,
      deletion_scheduled_for: user?.deletion_scheduled_for,
      marketing_consent: user?.marketing_consent,
      data_export_available: true,
    });
  } catch (err) {
    logger.error('GDPR status check failed', { userId, err: err.message });
    res.status(500).json({ error: 'Failed to get GDPR status', code: 'STATUS_CHECK_FAILED' });
  }
});

module.exports = router;
