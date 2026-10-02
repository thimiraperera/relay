'use strict';

// Recipient/sender address validation. Deliberately stricter than RFC 5322: no
// quoted local parts, IP literals, comments or internationalised addresses, so
// every accepted address is safe in SMTP commands and headers. All patterns are
// single character classes or bounded quantifiers (no nested repetition), so no
// input can make them backtrack.

const addressparser = require('nodemailer/lib/addressparser');
const { badRequest } = require('./errors');
const { stripCrlf } = require('./headers');

const LOCAL_CHARS = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$/;
const DOMAIN_LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
const ALPHA_TLD = /^[A-Za-z]{2,63}$/;
const PUNYCODE_TLD = /^xn--[A-Za-z0-9-]{1,59}$/i;

const MAX_LIST_BYTES = 64 * 1024;
const MAX_ITEM_CHARS = 1000;

function isValidEmail(s) {
  if (typeof s !== 'string' || s.length === 0 || s.length > 254) return false;
  const at = s.indexOf('@');
  if (at <= 0 || at !== s.lastIndexOf('@')) return false;

  const local = s.slice(0, at);
  if (local.length > 64 || !LOCAL_CHARS.test(local)) return false;
  if (local.startsWith('.') || local.endsWith('.') || local.includes('..')) return false;

  const labels = s.slice(at + 1).split('.');
  if (labels.length < 2) return false;
  for (const label of labels) {
    if (label.length === 0 || label.length > 63 || !DOMAIN_LABEL.test(label)) return false;
  }
  const tld = labels[labels.length - 1];
  return ALPHA_TLD.test(tld) || PUNYCODE_TLD.test(tld);
}

// addressparser reads "a@b.com c@d.com" (spaces instead of commas) as one address,
// a@b.com, with the display name "c@d.com", silently dropping a recipient. In
// input without display-name syntax (no quotes, no angle brackets) a "name" that
// is itself another address can only be that mistake, so it is refused.
const NAME_TOKEN_TRIM = /^[\s'(,;:]+|[\s'),;:.]+$/g;
function spaceSeparatedAddresses(raw, name, address) {
  if (!name.includes('@') || raw.includes('<') || raw.includes('"')) return false;
  const own = address.toLowerCase();
  for (const raw of name.split(/\s+/)) {
    const token = raw.replace(NAME_TOKEN_TRIM, '');
    if (token.includes('@') && isValidEmail(token) && token.toLowerCase() !== own) return true;
  }
  return false;
}

function invalid(field) {
  return badRequest(`invalid ${field} address`);
}

// Parses one string into [{ address, name }], rejecting groups, empty addresses
// (e.g. "Name <>" or bare words) and anything isValidEmail refuses.
function parseString(str, field) {
  const out = [];
  for (const entry of addressparser(str)) {
    if (!entry || entry.group !== undefined) throw invalid(field);
    const address = typeof entry.address === 'string' ? entry.address.trim() : '';
    if (!isValidEmail(address)) throw invalid(field);
    const name = stripCrlf(entry.name || '');
    if (spaceSeparatedAddresses(str, name, address)) throw invalid(field);
    out.push({ address, name });
  }
  return out;
}

// input: absent/null -> []; a comma-separated string (<= 64 KB); or an array of
// strings (each <= 1000 chars, at most `max` items when given).
function parseAddressList(input, field, { max } = {}) {
  if (input === undefined || input === null) return [];
  if (typeof input === 'string') {
    if (Buffer.byteLength(input, 'utf8') > MAX_LIST_BYTES) throw invalid(field);
    return parseString(input, field);
  }
  if (Array.isArray(input)) {
    if (Number.isInteger(max) && input.length > max) {
      throw badRequest(`too many recipients (max ${max})`);
    }
    const out = [];
    for (const item of input) {
      if (typeof item !== 'string' || item.length > MAX_ITEM_CHARS) throw invalid(field);
      for (const parsed of parseString(item, field)) out.push(parsed);
    }
    return out;
  }
  throw invalid(field);
}

function parseSingleAddress(input, field) {
  if (typeof input !== 'string' || input.length > MAX_ITEM_CHARS) throw invalid(field);
  const list = parseString(input, field);
  if (list.length !== 1) throw invalid(field);
  return list[0];
}

module.exports = { isValidEmail, parseAddressList, parseSingleAddress };
