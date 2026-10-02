'use strict';

// Header-bound values (subject, display names, reply-to, filenames, message ids)
// must never carry a line break: nodemailer encodes most of them safely, but the
// relay does not rely on that. U+0085, U+2028 and U+2029 are built with
// String.fromCharCode because typing them into a regex literal can store raw line
// terminators in the source file.
const CONTROL_CHARS = new RegExp(
  '[\\x00-\\x08\\x0A-\\x1F\\x7F' + String.fromCharCode(0x85, 0x2028, 0x2029) + ']',
  'g'
);
const SPACE_RUNS = / {2,}/g;

function stripCrlf(value) {
  if (typeof value !== 'string') return '';
  return value.replace(CONTROL_CHARS, ' ').replace(SPACE_RUNS, ' ').trim();
}

module.exports = { stripCrlf };
