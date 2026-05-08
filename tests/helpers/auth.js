'use strict';

const jwt        = require('jsonwebtoken');
const { v4: uuid } = require('uuid');

const TEST_USER = {
  id:    'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
  email: 'test@example.com',
  role:  'user',
  plan:  'pro',
};

const TEST_ADMIN = {
  id:    'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
  email: 'admin@example.com',
  role:  'admin',
  plan:  'enterprise',
};

function generateAccessToken(user = TEST_USER) {
  const jti = uuid();
  const token = jwt.sign(
    { email: user.email, role: user.role, plan: user.plan, jti },
    process.env.JWT_ACCESS_SECRET,
    {
      subject:   user.id,
      expiresIn: '15m',
      issuer:    'omnipublish-api',
      audience:  'omnipublish-client',
      algorithm: 'HS256',
    }
  );
  return { token, jti, user };
}

function generateRefreshToken(user = TEST_USER) {
  const jti = uuid();
  const token = jwt.sign(
    { jti },
    process.env.JWT_REFRESH_SECRET,
    {
      subject:   user.id,
      expiresIn: '7d',
      issuer:    'omnipublish-api',
      audience:  'omnipublish-client',
      algorithm: 'HS256',
    }
  );
  return { token, jti, user };
}

module.exports = { TEST_USER, TEST_ADMIN, generateAccessToken, generateRefreshToken };
