'use strict';

const express = require('express');
const router  = express.Router();
const crypto  = require('crypto');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { supabase }   = require('../config/database');
const { generateCSRFToken } = require('../middleware/csrf');
const { generateOAuthState, verifyOAuthState } = require('../middleware/oauthStateVerification');
const { BCRYPT_ROUNDS, JWT_CONFIG } = require('../config/security');
const { logger }            = require('../utils/logger');

const isProd = process.env.NODE_ENV === 'production';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

const hasGoogle = !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);

function getFrontendOrigin(req) {
  const fallback = process.env.FRONTEND_URL || process.env.APP_URL || 'http://localhost:4000';
  const candidates = [req.get('origin'), req.get('referer')].filter(Boolean);

  for (const candidate of candidates) {
    try {
      const origin = new URL(candidate).origin;
      if (!ALLOWED_ORIGINS.length || ALLOWED_ORIGINS.includes(origin)) return origin;
    } catch {
      // ignore malformed headers
    }
  }

  return fallback;
}

async function upsertGoogleOAuthUser(email, fullName) {
  let { data: user } = await supabase.from('users')
    .select('id, email, role, plan, full_name, is_verified')
    .eq('email', email)
    .single();

  if (!user) {
    const fallbackPasswordHash = await bcrypt.hash(crypto.randomBytes(32).toString('hex'), BCRYPT_ROUNDS);
    const baseUser = {
      id: uuidv4(),
      email,
      full_name: fullName,
      role: 'user',
      plan: 'free',
      is_active: true,
      is_verified: true,
      last_login_at: new Date(),
    };

    const { data: created, error } = await supabase.from('users')
      .insert({ ...baseUser, password_hash: fallbackPasswordHash })
      .select('id, email, role, plan, full_name, is_verified')
      .single();

    if (error) throw error;

    logger.info('Google OAuth new user created', { userId: created.id });
    return created;
  }

  const { data: updated, error } = await supabase.from('users')
    .update({
      is_verified: true,
      last_login_at: new Date(),
      full_name: user.full_name || fullName || null,
    })
    .eq('id', user.id)
    .select('id, email, role, plan, full_name, is_verified')
    .single();

  if (error) throw error;

  return updated || { ...user, is_verified: true };
}

if (hasGoogle) {
  const passport       = require('passport');
  const GoogleStrategy = require('passport-google-oauth20').Strategy;

  passport.use(new GoogleStrategy({
    clientID:     process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL:  `${process.env.APP_URL || 'http://localhost:4000'}/api/v1/auth/google/callback`,
  }, async (_accessToken, _refreshToken, profile, done) => {
    try {
      const email    = profile.emails?.[0]?.value;
      const fullName = profile.displayName || profile.name?.givenName || null;
      if (!email) return done(new Error('No email from Google'));
      const user = await upsertGoogleOAuthUser(email, fullName);
      done(null, user);
    } catch (err) {
      done(err);
    }
  }));

  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => {
    const { data } = await supabase.from('users').select('id, email, role, plan').eq('id', id).single();
    done(null, data);
  });

  router.get('/google',
    async (req, res, next) => {
      try {
        const { state } = await generateOAuthState('google', null, getFrontendOrigin(req));
        passport.authenticate('google', { scope: ['profile', 'email'], session: false, state })(req, res, next);
      } catch (err) {
        logger.error('OAuth initialisation error', { err: err.message });
        res.redirect('/?oauth_error=init_failed');
      }
    }
  );

  router.get('/google/callback',
    async (req, res, next) => {
      try {
        const { returnTo } = await verifyOAuthState(req.query.state, 'google');
        req.oauthReturnTo = returnTo || getFrontendOrigin(req);
        next();
      } catch {
        res.redirect('/?oauth_error=invalid_state');
      }
    },
    passport.authenticate('google', { session: false, failureRedirect: '/?oauth_error=1' }),
    async (req, res) => {
      try {
        const code = jwt.sign(
          { purpose: 'oauth_exchange', userId: req.user.id, email: req.user.email },
          JWT_CONFIG.accessSecret,
          {
            expiresIn: '10m',
            issuer: JWT_CONFIG.issuer,
            audience: JWT_CONFIG.audience,
            algorithm: JWT_CONFIG.algorithm,
          }
        );

        // Set CSRF cookie now so frontend can use it immediately after exchange
        const csrfToken = generateCSRFToken();
        res.cookie('csrf_token', csrfToken, { httpOnly: false, secure: isProd, sameSite: 'Strict', maxAge: 15 * 60 * 1000 });

        // Redirect with signed exchange code only — no tokens in URL
        res.redirect(`${req.oauthReturnTo || getFrontendOrigin(req)}/?oauth_code=${code}#onboarding`);
      } catch (err) {
        logger.error('OAuth callback error', { err: err.message });
        res.redirect('/?oauth_error=1');
      }
    }
  );
} else {
  // Stub — frontend shows "coming soon" toast
  router.get('/google', (_req, res) => {
    res.redirect('/?oauth_error=not_configured');
  });
}

module.exports = router;
module.exports.upsertGoogleOAuthUser = upsertGoogleOAuthUser;
