'use strict';

const { logger } = require('./logger');

const setupGracefulShutdown = (server, resources = {}) => {
  let isShuttingDown = false;

  const shutdown = async (signal) => {
    if (isShuttingDown) return;
    isShuttingDown = true;

    logger.info('Received shutdown signal', { signal });

    const forceExit = setTimeout(() => {
      logger.error('Graceful shutdown timed out');
      process.exit(1);
    }, 45000);

    try {
      await new Promise((resolve) => {
        server.close(() => resolve());
      });

      if (resources.redis?.quit) await resources.redis.quit();
      if (resources.supabase?.close) await resources.supabase.close();
      if (Array.isArray(resources.cronJobs)) {
        resources.cronJobs.forEach((job) => job?.stop?.());
      }

      clearTimeout(forceExit);
      process.exit(0);
    } catch (err) {
      clearTimeout(forceExit);
      logger.error('Graceful shutdown failed', { err: err.message });
      process.exit(1);
    }
  };

  process.on('SIGINT', () => {
    shutdown('SIGINT');
  });
  process.on('SIGTERM', () => {
    shutdown('SIGTERM');
  });
};

module.exports = { setupGracefulShutdown };
