'use strict';

// The client IP as Express computes it from the `trust proxy` setting (the
// right-most X-Forwarded-For entry LiteSpeed appended, with TRUST_PROXY=1).
// Everything that keys on the client address goes through here so IPv4-mapped
// IPv6 addresses ("::ffff:1.2.3.4") and IPv4 addresses are treated alike.

const net = require('node:net');

const MAPPED_PREFIX = '::ffff:';

// Lowercases, drops an IPv6 zone index ("fe80::1%eth0") and unwraps
// IPv4-mapped addresses. Returns null for anything that is not an IP address.
function canonicalIp(value) {
  if (typeof value !== 'string' || value === '') return null;
  let ip = value.trim().toLowerCase();
  const zone = ip.indexOf('%');
  if (zone !== -1) ip = ip.slice(0, zone);
  if (ip.startsWith(MAPPED_PREFIX) && net.isIPv4(ip.slice(MAPPED_PREFIX.length))) {
    ip = ip.slice(MAPPED_PREFIX.length);
  }
  return net.isIP(ip) ? ip : null;
}

function clientIp(req) {
  return canonicalIp(req ? req.ip : undefined);
}

// Expands an IPv6 address to its 8 hextets, without leading zeros. Accepts a
// trailing dotted IPv4 part ("64:ff9b::1.2.3.4"). Caller has validated the input.
function ipv6Hextets(ip) {
  let s = ip;
  const lastColon = s.lastIndexOf(':');
  const tail = s.slice(lastColon + 1);
  if (tail.includes('.')) {
    const o = tail.split('.').map(Number);
    s = s.slice(0, lastColon + 1) + ((o[0] << 8) | o[1]).toString(16) + ':' + ((o[2] << 8) | o[3]).toString(16);
  }
  const halves = s.split('::');
  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
  const fill = halves.length > 1 ? 8 - head.length - rest.length : 0;
  const groups = head.concat(new Array(fill).fill('0'), rest);
  return groups.map((g) => parseInt(g, 16).toString(16));
}

const V6_PREFIXES = new Set([16, 32, 48, 64, 80, 96, 112]);

// Rate-limit key for an address: IPv4 as is; IPv6 by its /64 by default,
// because a single host or customer usually controls a whole /64 and could
// rotate through it. `v6Prefix` (a multiple of 16) widens that: sign-in uses
// /48, the allocation a single customer or site commonly gets, so rotating
// through its 65,536 /64s does not multiply the sign-in budget.
function ipRateKey(ip, { v6Prefix = 64 } = {}) {
  if (!V6_PREFIXES.has(v6Prefix)) throw new RangeError(`ipRateKey: unsupported IPv6 prefix /${v6Prefix}`);
  const canonical = canonicalIp(ip);
  if (!canonical) return null;
  if (net.isIPv4(canonical)) return canonical;
  return ipv6Hextets(canonical).slice(0, v6Prefix / 16).join(':') + `::/${v6Prefix}`;
}

module.exports = { clientIp, ipRateKey, canonicalIp };
