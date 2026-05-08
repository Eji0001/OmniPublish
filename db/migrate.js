'use strict';

require('dotenv').config();
const { Client } = require('pg');
const fs         = require('fs');
const path       = require('path');

const MIGRATIONS_DIR = path.join(__dirname, 'migrations');

const CYAN  = '\x1b[36m';
const GREEN = '\x1b[32m';
const RED   = '\x1b[31m';
const DIM   = '\x1b[2m';
const RESET = '\x1b[0m';

async function migrate() {
  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) {
    console.error(`${RED}ERROR: DATABASE_URL is not set in .env${RESET}`);
    process.exit(1);
  }

  const client = new Client({ connectionString: dbUrl, ssl: { rejectUnauthorized: false } });
  await client.connect();
  console.log(`${CYAN}Connected to database${RESET}\n`);

  try {
    // Ensure the migrations tracking table exists
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        id         SERIAL       PRIMARY KEY,
        filename   VARCHAR(255) UNIQUE NOT NULL,
        applied_at TIMESTAMPTZ  DEFAULT NOW() NOT NULL
      );
    `);

    // Load the set of already-applied migrations
    const { rows } = await client.query('SELECT filename FROM schema_migrations ORDER BY filename');
    const applied  = new Set(rows.map(r => r.filename));

    // Read and sort migration files
    const files = fs.readdirSync(MIGRATIONS_DIR)
      .filter(f => f.endsWith('.sql'))
      .sort();

    if (!files.length) {
      console.log(`${DIM}No migration files found in ${MIGRATIONS_DIR}${RESET}`);
      return;
    }

    let appliedCount = 0;
    let skippedCount = 0;

    for (const file of files) {
      if (applied.has(file)) {
        console.log(`  ${DIM}skip   ${file}${RESET}`);
        skippedCount++;
        continue;
      }

      const sql = fs.readFileSync(path.join(MIGRATIONS_DIR, file), 'utf8');

      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query(
          'INSERT INTO schema_migrations (filename) VALUES ($1)',
          [file]
        );
        await client.query('COMMIT');
        console.log(`  ${GREEN}apply  ${file}${RESET}`);
        appliedCount++;
      } catch (err) {
        await client.query('ROLLBACK');
        throw Object.assign(err, { migration: file });
      }
    }

    console.log(
      `\n${GREEN}Done.${RESET} ` +
      `${appliedCount} applied, ${skippedCount} already up-to-date.\n`
    );
  } finally {
    await client.end();
  }
}

migrate().catch(err => {
  const label = err.migration ? `[${err.migration}]` : '';
  console.error(`\n${RED}Migration failed ${label}${RESET}`);
  console.error(err.message);
  if (err.detail)   console.error('Detail:', err.detail);
  if (err.position) console.error('Position:', err.position);
  process.exit(1);
});
