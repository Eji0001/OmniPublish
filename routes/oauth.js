'use strict';

const express = require('express');
const router  = express.Router();
const crypto  = require('crypto');
const bcrypt  = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { supabase }   = require('../config/database');
const { generateCSRFToken } = require('../middleware/csrf');
const { generateOAuthState, verifyOAuthState } = require('../middleware/oauthStateVerification');
const { BCRYPT_ROUNDS } = require('../config/security');
const { logger }            = require('../utils/logger');
const { issueConfirmationLink } = require('../services/authLinkService');

const isProd = process.env.NODE_ENV === 'production';

const hasGoogle = !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);

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

      let { data: user } = await supabase.from('users')
        .select('id, email, role, plan, full_name, is_verified').eq('email', email).single();

      if (!user) {
        const baseUser = { id: uuidv4(), email, full_name: fullName, role: 'user', plan: 'free', is_active: true, is_verified: false };
        const insertUser = async (passwordHash) => supabase.from('users')
          .insert({ ...baseUser, password_hash: passwordHash })
          .select('id, email, role, plan, full_name, is_verified')
          .single();

        let createdRes = await insertUser(null);
        if (createdRes.error && (createdRes.error.code === '23502' || /null value in column .*password_hash/i.test(createdRes.error.message || ''))) {
          const fallbackHash = await bcrypt.hash(crypto.randomBytes(32).toString('hex'), BCRYPT_ROUNDS);
          createdRes = await insertUser(fallbackHash);
        }
        if (createdRes.error) return done(createdRes.error);
        user = createdRes.data;
        logger.info('Google OAuth new user created', { userId: user.id });
      } else {
        await supabase.from('users').update({ last_login_at: new Date() }).eq('id', user.id);
      }

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
        const { state } = await generateOAuthState('google');
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
        await verifyOAuthState(req.query.state, 'google');
        next();
      } catch {
        res.redirect('/?oauth_error=invalid_state');
      }
    },
    passport.authenticate('google', { session: false, failureRedirect: '/?oauth_error=1' }),
    async (req, res) => {
      try {
        if (!req.user?.is_verified) {
          try {
            await issueConfirmationLink(req.user, {
              subject: 'Confirm your OmniPublish email',
              headline: 'Confirm your email to finish Google sign-in',
              cta: 'Confirm and continue onboarding',
            });
            res.redirect('/?verify_sent=1');
            return;
          } catch (err) {
            logger.error('Verification email send failed', { err: err.message, userId: req.user.id });
            res.redirect('/?oauth_error=verify_failed');
            return;
          }
        }

        // Issue a short-lived one-time exchange code (5 min) stored in password_resets
        const code     = crypto.randomBytes(24).toString('hex');
        const codeHash = crypto.createHash('sha256').update(code).digest('hex');
        await supabase.from('password_resets').insert({
          id: uuidv4(), user_id: req.user.id,
          token_hash: codeHash,
          purpose: 'oauth_exchange',
          expires_at: new Date(Date.now() + 5 * 60 * 1000),
        });

        // Set CSRF cookie now so frontend can use it immediately after exchange
        const csrfToken = generateCSRFToken();
        res.cookie('csrf_token', csrfToken, { httpOnly: false, secure: isProd, sameSite: 'Strict', maxAge: 15 * 60 * 1000 });

        // Redirect with opaque code only — no tokens in URL
        res.redirect(`/?oauth_code=${code}#onboarding`);
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
