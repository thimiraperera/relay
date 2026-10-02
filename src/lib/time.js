'use strict';

// Time helpers. The app stores UTC everywhere; "local" means config.timezone
// (RELAY_TIMEZONE, an IANA zone such as Asia/Colombo).

const formatterCache = new Map();

function partsFormatter(tz) {
  let f = formatterCache.get(tz);
  if (!f) {
    f = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      hourCycle: 'h23',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
    formatterCache.set(tz, f);
  }
  return f;
}

function localParts(date, tz) {
  const out = {};
  for (const p of partsFormatter(tz).formatToParts(date)) out[p.type] = p.value;
  return out;
}

// 'YYYY-MM-DD' of `date` in time zone `tz`.
function localDay(date, tz) {
  const p = localParts(date, tz);
  return `${p.year}-${p.month}-${p.day}`;
}

// 'YYYY-MM-DD HH:mm:ss' of `date` in time zone `tz`.
function localDateTime(date, tz) {
  const p = localParts(date, tz);
  return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}:${p.second}`;
}

// Calendar arithmetic on 'YYYY-MM-DD' strings (time-zone independent).
function addDays(day, n) {
  const d = new Date(`${day}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + n);
  return d.toISOString().slice(0, 10);
}

function isDayString(s) {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(`${s}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s;
}

const systemClock = Object.freeze({ now: () => new Date() });

module.exports = { localDay, localDateTime, addDays, isDayString, systemClock };
