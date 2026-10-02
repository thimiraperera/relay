'use strict';

// Attachment validation. The file type comes from the extension and is verified
// against the decoded content; the caller's content_type is advisory only and
// never used (a PHP app may send application/octet-stream for everything).

const { badRequest, tooLarge } = require('./errors');
const { stripCrlf } = require('./headers');

const PK_ZIP = [0x50, 0x4b, 0x03, 0x04];
const HEIF_BRANDS = new Set(['heic', 'heix', 'hevc', 'hevx', 'heim', 'heis', 'mif1', 'msf1']);

// Every attachment is charged its decoded bytes plus this much for its MIME part
// (boundary, Content-Type/Disposition headers, base64 line breaks of small
// files). Without it a request of many tiny attachments stayed under the size
// limit while the composed message, and the memory spent building it, grew
// without bound.
const MIME_PART_OVERHEAD = 1024;
// The filename is charged on top, per UTF-8 byte: it appears twice (name= and
// filename=), and a non-ASCII name is encoded at three characters per byte in
// both places (RFC 2231 percent-encoding, RFC 2047 Q-encoding). Measured with
// nodemailer's composer: a 200-character Sinhala or CJK name (592 bytes) adds
// about 3,500 header bytes, 5.94 per byte; an ASCII name about 2.2 per byte.
const FILENAME_BYTE_FACTOR = 6;

// The charged size of one attachment. normalizeAttachments' running total,
// totalAttachmentBytes and the rejected-row estimate in services/send.js all
// use it, so the three always agree.
function attachmentCharge(decodedBytes, filename) {
  const nameBytes = typeof filename === 'string' ? Buffer.byteLength(filename, 'utf8') : 0;
  return decodedBytes + MIME_PART_OVERHEAD + FILENAME_BYTE_FACTOR * nameBytes;
}

function startsWith(buf, bytes, offset = 0) {
  if (buf.length < offset + bytes.length) return false;
  for (let i = 0; i < bytes.length; i++) {
    if (buf[offset + i] !== bytes[i]) return false;
  }
  return true;
}

function asciiAt(buf, text, offset = 0) {
  return startsWith(buf, Buffer.from(text, 'latin1'), offset);
}

function isPdf(buf) {
  return buf.subarray(0, 1024).indexOf('%PDF-', 0, 'latin1') !== -1;
}

function isHeif(buf) {
  return asciiAt(buf, 'ftyp', 4) && buf.length >= 12 && HEIF_BRANDS.has(buf.toString('latin1', 8, 12));
}

// Plain text must not contain NUL bytes, except UTF-16 text (BOM first), where
// NUL bytes are normal.
function isText(buf) {
  if (startsWith(buf, [0xff, 0xfe]) || startsWith(buf, [0xfe, 0xff])) return true;
  return buf.indexOf(0) === -1;
}

const TYPES = {
  pdf: { contentType: 'application/pdf', check: isPdf },
  jpg: { contentType: 'image/jpeg', check: (b) => startsWith(b, [0xff, 0xd8, 0xff]) },
  jpeg: { contentType: 'image/jpeg', check: (b) => startsWith(b, [0xff, 0xd8, 0xff]) },
  png: {
    contentType: 'image/png',
    check: (b) => startsWith(b, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  },
  gif: { contentType: 'image/gif', check: (b) => asciiAt(b, 'GIF87a') || asciiAt(b, 'GIF89a') },
  webp: { contentType: 'image/webp', check: (b) => asciiAt(b, 'RIFF') && asciiAt(b, 'WEBP', 8) },
  heic: { contentType: 'image/heic', check: isHeif },
  heif: { contentType: 'image/heif', check: isHeif },
  bmp: { contentType: 'image/bmp', check: (b) => asciiAt(b, 'BM') },
  tif: {
    contentType: 'image/tiff',
    check: (b) => startsWith(b, [0x49, 0x49, 0x2a, 0x00]) || startsWith(b, [0x4d, 0x4d, 0x00, 0x2a]),
  },
  tiff: {
    contentType: 'image/tiff',
    check: (b) => startsWith(b, [0x49, 0x49, 0x2a, 0x00]) || startsWith(b, [0x4d, 0x4d, 0x00, 0x2a]),
  },
  csv: { contentType: 'text/csv', check: isText },
  txt: { contentType: 'text/plain', check: isText },
  docx: {
    contentType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    check: (b) => startsWith(b, PK_ZIP),
  },
  xlsx: {
    contentType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    check: (b) => startsWith(b, PK_ZIP),
  },
};

const ALLOWED_EXTENSIONS = Object.freeze(Object.keys(TYPES));

const WHITESPACE = /\s+/g;
const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;
const PATH_SEPARATORS = /[/\\]/;

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function cleanFilename(raw) {
  const parts = stripCrlf(raw).split(PATH_SEPARATORS);
  const name = parts[parts.length - 1].trim();
  if (name.length < 1 || name.length > 200) throw badRequest('invalid attachment filename');
  return name;
}

function extensionOf(filename) {
  const dot = filename.lastIndexOf('.');
  return dot === -1 ? '' : filename.slice(dot + 1).toLowerCase();
}

// list: the request's `attachments` value. maxBytes: the size budget for all
// attachments together, each charged attachmentCharge() (decoded bytes +
// MIME_PART_OVERHEAD + FILENAME_BYTE_FACTOR per filename byte); exceeding it is
// a 413 before more data is decoded.
function normalizeAttachments(list, { maxBytes }) {
  if (list === undefined || list === null) return [];
  if (!Array.isArray(list)) throw badRequest('attachments must be an array');

  const maxBase64Length = Math.ceil((maxBytes * 4) / 3) + 4;
  const out = [];
  let total = 0;
  for (const item of list) {
    if (
      !isPlainObject(item) ||
      typeof item.filename !== 'string' ||
      typeof item.content_base64 !== 'string' ||
      (item.content_type !== undefined && item.content_type !== null && typeof item.content_type !== 'string')
    ) {
      throw badRequest('invalid attachment');
    }

    // Line-wrapped base64 (76 chars + CRLF, as PHP's chunk_split produces) is
    // valid; measure it without the whitespace so wrapping cannot cause a 413.
    const b64 = item.content_base64.replace(WHITESPACE, '');
    if (b64.length > maxBase64Length) throw tooLarge('message too large');

    const filename = cleanFilename(item.filename);
    const ext = extensionOf(filename);
    const type = Object.prototype.hasOwnProperty.call(TYPES, ext) ? TYPES[ext] : null;
    if (!type) throw badRequest(`attachment type not allowed: ${ext.slice(0, 10) || '(none)'}`);

    if (b64.length % 4 !== 0 || !BASE64.test(b64)) throw badRequest('attachment is not valid base64');
    const content = Buffer.from(b64, 'base64');
    if (content.length === 0) throw badRequest('attachment is empty');
    total += attachmentCharge(content.length, filename);
    if (total > maxBytes) throw tooLarge('message too large');
    if (!type.check(content)) throw badRequest('attachment content does not match file type');

    out.push({ filename, contentType: type.contentType, content });
  }
  return out;
}

// The same charged total that normalizeAttachments checks.
function totalAttachmentBytes(list) {
  let total = 0;
  for (const a of list || []) total += attachmentCharge(a.content.length, a.filename);
  return total;
}

module.exports = {
  normalizeAttachments,
  totalAttachmentBytes,
  attachmentCharge,
  ALLOWED_EXTENSIONS,
  MIME_PART_OVERHEAD,
  FILENAME_BYTE_FACTOR,
};
