'use strict';

// Plain-text alternative for HTML-only messages. html-to-text has no depth or
// child limits by default (superlinear on large tables, RangeError on deep
// nesting), so the input is sliced and the converter is bounded. Any failure just
// means the message goes out HTML-only.
//
// Tables: html-to-text renders a table that is not a "data table" as a block
// whose rows and cells are inline, so `<tr><td>Name:</td><td>Kamal</td></tr>
// <tr><td>NIC:</td>…` came out as "Name:KamalNIC:…". Transactional mail is
// mostly such tables, so each row is made a line and a space is put before every
// closing cell tag (inline whitespace then collapses to a single space).

const { compile } = require('html-to-text');

const MAX_INPUT_CHARS = 262144;
const CELL_END = /<\/t[dh]\s*>/gi;

const convert = compile({
  wordwrap: 100,
  limits: {
    maxInputLength: MAX_INPUT_CHARS,
    maxDepth: 40,
    maxChildNodes: 2000,
    ellipsis: '...',
  },
  selectors: [
    { selector: 'img', format: 'skip' },
    { selector: 'a', options: { hideLinkHrefIfSameAsText: true } },
    { selector: 'tr', format: 'block', options: { leadingLineBreaks: 1, trailingLineBreaks: 1 } },
  ],
});

// Slicing ourselves keeps html-to-text from hitting maxInputLength, where it
// prints a warning to the console. A lone high surrogate left at the cut is dropped.
function sliceInput(s) {
  let src = s.length > MAX_INPUT_CHARS ? s.slice(0, MAX_INPUT_CHARS) : s;
  const last = src.charCodeAt(src.length - 1);
  if (last >= 0xd800 && last <= 0xdbff) src = src.slice(0, -1);
  return src;
}

function htmlToText(html) {
  if (typeof html !== 'string' || html === '') return null;
  // Sliced before and after the cell spaces are added: the first keeps the
  // replace cheap on large bodies, the second keeps the result within the limit.
  const src = sliceInput(sliceInput(html).replace(CELL_END, ' $&'));
  try {
    const text = convert(src);
    return typeof text === 'string' && text.trim() !== '' ? text : null;
  } catch {
    return null;
  }
}

module.exports = { htmlToText };
