'use strict';

module.exports = {
  apps: [
    {
      name: 'omnipublish',
      script: 'server.js',

      // Cluster mode: one worker per CPU core
      instances: 'max',
      exec_mode: 'cluster',

      // Cap heap before OOM kill
      node_args: '--max-old-space-size=512',
      max_memory_restart: '512M',

      // Production env injected by IONOS / CI — never hard-code secrets here
      env_production: {
        NODE_ENV: 'production',
      },

      // Log paths (logs/ dir must be writable)
      error_file: './logs/pm2-error.log',
      out_file:   './logs/pm2-out.log',
      merge_logs: true,
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',

      watch: false,
      autorestart: true,
      restart_delay: 5000,
      max_restarts: 10,
    },
  ],
};
