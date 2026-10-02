'use strict';

// Per-app IP allowlists: IPv4/IPv6 addresses or CIDR ranges. Entries are stored
// normalised (lowercase, IPv4-mapped IPv6 unwrapped) so they compare the same way
// clientIp() reports addresses.

const net = require('node:net');
const { canonicalIp } = require('./clientIp');

const MAPPED_PREFIX = '::ffff:';

// Returns the normalised entry string, or null if it is not an address or CIDR.
function normalizeEntry(raw) {
  const parts = raw.trim().split('/');
  if (parts.length > 2) return null;
  const [addrPart, bitsPart] = parts;
  if (addrPart.includes('%')) return null;

  let addr = addrPart.toLowerCase();
  let family = net.isIP(addr);
  if (!family) return null;
  if (bitsPart === undefined) return canonicalIp(addr);
  if (!/^\d{1,3}$/.test(bitsPart)) return null;

  let bits = Number(bitsPart);
  // "::ffff:10.0.0.0/104" is the IPv4 range 10.0.0.0/8.
  if (family === 6 && addr.startsWith(MAPPED_PREFIX) && net.isIPv4(addr.slice(MAPPED_PREFIX.length)) && bits >= 96) {
    addr = addr.slice(MAPPED_PREFIX.length);
    bits -= 96;
    family = 4;
  }
  if (bits > (family === 4 ? 32 : 128)) return null;
  return `${addr}/${bits}`;
}

// input: an array of strings, or a string with one entry per line or comma.
// Returns { entries, errors } with duplicates removed and one error per bad entry.
function parseAllowlist(input) {
  let items;
  if (input === undefined || input === null) items = [];
  else if (Array.isArray(input)) items = input;
  else if (typeof input === 'string') items = input.split(/[\r\n,]+/);
  else return { entries: [], errors: ['IP allowlist must be a list of addresses'] };

  const entries = [];
  const errors = [];
  const seen = new Set();
  for (const item of items) {
    if (typeof item !== 'string') {
      errors.push('IP allowlist entries must be text');
      continue;
    }
    const trimmed = item.trim();
    if (trimmed === '') continue;
    const entry = normalizeEntry(trimmed);
    if (!entry) {
      errors.push(`"${trimmed.slice(0, 60)}" is not a valid IP address or CIDR range`);
      continue;
    }
    if (!seen.has(entry)) {
      seen.add(entry);
      entries.push(entry);
    }
  }
  return { entries, errors };
}

function buildBlockList(entries) {
  const list = new net.BlockList();
  for (const raw of entries) {
    if (typeof raw !== 'string') continue;
    // Stored lists were validated on save; re-check so a hand-edited row cannot
    // make addSubnet/addAddress throw on every request.
    const entry = normalizeEntry(raw);
    if (!entry) continue;
    const [addr, bits] = entry.split('/');
    const type = net.isIPv4(addr) ? 'ipv4' : 'ipv6';
    if (bits === undefined) list.addAddress(addr, type);
    else list.addSubnet(addr, Number(bits), type);
  }
  return list;
}

// Empty list = no restriction. Unknown client IP = not allowed.
function isIpAllowed(entries, ip) {
  if (!Array.isArray(entries) || entries.length === 0) return true;
  const canonical = canonicalIp(ip);
  if (!canonical) return false;
  return buildBlockList(entries).check(canonical, net.isIPv4(canonical) ? 'ipv4' : 'ipv6');
}

module.exports = { parseAllowlist, isIpAllowed };
