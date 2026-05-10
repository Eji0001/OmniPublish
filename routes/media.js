/**
 * routes/media.js — Secure media upload with image optimisation
 */

'use strict';

const express = require('express');
const multer = require('multer');
const path = require('path');
const sharp = require('sharp');
const { v4: uuid } = require('uuid');
const { supabase } = require('../config/database');
const { verifyToken } = require('../middleware/auth');
const { mediaRateLimiter } = require('../middleware/rateLimit');
const { ALLOWED_MEDIA_TYPES, MAX_FILE_SIZE } = require('../config/security');

const router = express.Router();
router.use(verifyToken);

const storage = multer.memoryStorage();
const fileFilter = (req, file, cb) => {
  const all = [...ALLOWED_MEDIA_TYPES.image, ...ALLOWED_MEDIA_TYPES.video];
  all.includes(file.mimetype) ? cb(null, true) : cb(new Error(`File type ${file.mimetype} not allowed`), false);
};
const upload = multer({ storage, fileFilter, limits: { fileSize: MAX_FILE_SIZE.video, files: 10 } });

/* ── POST /media/upload ── */
router.post('/upload', mediaRateLimiter, upload.array('files', 10), async (req, res) => {
  if (!req.files?.length) return res.status(422).json({ error: 'No files uploaded' });

  const bucket = process.env.SUPABASE_STORAGE_BUCKET || 'media';
  const results = await Promise.allSettled(req.files.map(async (file) => {
    const isImage = ALLOWED_MEDIA_TYPES.image.includes(file.mimetype);
    const maxSize = isImage ? MAX_FILE_SIZE.image : MAX_FILE_SIZE.video;
    if (file.size > maxSize) throw new Error(`${file.originalname} exceeds size limit`);

    let buffer = file.buffer;
    let width, height;

    if (isImage) {
      const meta = await sharp(buffer).metadata();
      width = meta.width;
      height = meta.height;
      buffer = await sharp(buffer)
        .resize({ width: 3840, height: 2160, fit: 'inside', withoutEnlargement: true })
        .webp({ quality: 85 }).toBuffer();
      file.mimetype = 'image/webp';
    }

    const ext = isImage ? 'webp' : path.extname(file.originalname).slice(1);
    const filename = `${req.user.id}/${uuid()}.${ext}`;

    const { error: storageErr } = await supabase.storage.from(bucket).upload(filename, buffer, { contentType: file.mimetype, upsert: false });
    if (storageErr) throw new Error(`Storage upload failed: ${storageErr.message}`);

    const { data: { publicUrl } } = supabase.storage.from(bucket).getPublicUrl(filename);
    const { data: record } = await supabase.from('media_files').insert({
      user_id: req.user.id, filename, original_name: file.originalname.slice(0, 255),
      mime_type: file.mimetype, size_bytes: file.size, storage_path: filename,
      cdn_url: publicUrl, width: width || null, height: height || null,
    }).select().single();

    return { id: record.id, url: publicUrl, mimeType: file.mimetype, width, height };
  }));

  const uploaded = results.filter(r => r.status === 'fulfilled').map(r => r.value);
  const errors = results.filter(r => r.status === 'rejected').map(r => r.reason.message);
  res.status(errors.length === results.length ? 500 : 201).json({ uploaded, errors });
});

/* ── DELETE /media/:id ── */
router.delete('/:id', async (req, res) => {
  const { data: file } = await supabase.from('media_files').select('storage_path, user_id').eq('id', req.params.id).single();
  if (!file || file.user_id !== req.user.id) return res.status(404).json({ error: 'File not found' });
  await supabase.storage.from(process.env.SUPABASE_STORAGE_BUCKET || 'media').remove([file.storage_path]);
  await supabase.from('media_files').delete().eq('id', req.params.id);
  res.status(204).send();
});

module.exports = router;
