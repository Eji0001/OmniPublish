/**
 * utils/logger.js — Winston structured JSON logger
 * Covers: SOC 2 CC7.2 (audit trail)
 */

'use strict';

const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');

const { combine, timestamp, json, errors, colorize, simple } = winston.format;

const isProd = process.env.NODE_ENV === 'production';

const transports = [
  new winston.transports.Console({
    format: isProd ? combine(timestamp(), json()) : combine(colorize(), simple()),
    silent: process.env.NODE_ENV === 'test',
  }),
];

if (isProd) {
  transports.push(
    new DailyRotateFile({
      filename:      'logs/app-%DATE%.log',
      datePattern:   'YYYY-MM-DD',
      maxFiles:      '14d',
      zippedArchive: true,
      format:        combine(timestamp(), errors({ stack: true }), json()),
    }),
    new DailyRotateFile({
      filename:      'logs/error-%DATE%.log',
      datePattern:   'YYYY-MM-DD',
      level:         'error',
      maxFiles:      '30d',
      zippedArchive: true,
      format:        combine(timestamp(), errors({ stack: true }), json()),
    })
  );
}

const logger = winston.createLogger({
  level:       process.env.LOG_LEVEL || (isProd ? 'info' : 'debug'),
  format:      combine(timestamp(), errors({ stack: true }), json()),
  transports,
  exitOnError: false,
});

module.exports = { logger };
