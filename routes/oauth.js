'use strict';

const express = require('express');
const router  = express.Router();

const hasGoogle = !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);

if (hasGoogle) {
  const passport       = require('passport');
  const GoogleStrategy = require('passport-google-oauth20').Strategy;
  const { v4: uuidv4 } = require('uuid');
  const { supabase }   = require('../config/database');
  const { issueTokens }       = require('../middleware/auth');
  const { generateCSRFToken } = require('../middleware/csrf');
  const { logger }            = require('../utils/logger');

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
        .select('id, email, role, plan').eq('email', email).single();

      if (!user) {
        const { data: created, error } = await supabase.from('users')
          .insert({ id: uuidv4(), email, full_name: fullName, password_hash: null, role: 'user', plan: 'free', is_active: true })
          .select('id, email, role, plan').single();
        if (error) return done(error);
        user = created;
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
    passport.authenticate('google', { scope: ['profile', 'email'], session: false })
  );

  router.get('/google/callback',
    passport.authenticate('google', { session: false, failureRedirect: '/?oauth_error=1' }),
    (req, res) => {
      const tokens    = issueTokens(req.user);
      const csrfToken = generateCSRFToken();
      res.cookie('csrf_token', csrfToken, {
        httpOnly: false,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Strict',
        maxAge: 15 * 60 * 1000,
      });
      const payload = encodeURIComponent(JSON.stringify({ ...tokens, csrfToken, user: req.user }));
      res.redirect(`/?oauth=${payload}#onboarding`);
    }
  );
} else {
  // Stub — tells the frontend to show "coming soon" toast
  router.get('/google', (_req, res) => {
    res.redirect('/?oauth_error=not_configured');
  });
}

module.exports = router;
