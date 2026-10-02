'use strict';

// Display helpers for the admin views (`fmt` in every template). Dates are shown
// in config.timezone; relative times are measured against deps.clock so tests
// with a fake clock render predictably.

const { localDay, localDateTime, isDayString, systemClock } = require('./time');

const EMPTY = '—';
const numberFormat = new Intl.NumberFormat('en-US');

function toDate(d) {
  if (d === null || d === undefined || d === '') return null;
  const date = d instanceof Date ? d : new Date(d);
  return Number.isNaN(date.getTime()) ? null : date;
}

// 'YYYY-MM-DD HH:mm:ss' in `tz`; DATE column strings pass through.
function dateTime(d, tz = 'UTC') {
  if (isDayString(d)) return d;
  const date = toDate(d);
  return date ? localDateTime(date, tz) : EMPTY;
}

function date(d, tz = 'UTC') {
  if (isDayString(d)) return d;
  const dt = toDate(d);
  return dt ? localDay(dt, tz) : EMPTY;
}

function unit(n, word) {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

// "just now", "5 minutes ago", "in 2 hours"; older than 30 days → the date.
function relative(d, now = new Date(), tz = 'UTC') {
  const date = toDate(d);
  if (!date) return 'never';
  const diffMs = now.getTime() - date.getTime();
  const future = diffMs < 0;
  const s = Math.abs(diffMs) / 1000;
  let text;
  if (s < 45) return future ? 'in a few seconds' : 'just now';
  if (s < 90) text = unit(1, 'minute');
  else if (s < 45 * 60) text = unit(Math.round(s / 60), 'minute');
  else if (s < 90 * 60) text = unit(1, 'hour');
  else if (s < 22 * 3600) text = unit(Math.round(s / 3600), 'hour');
  else if (s < 36 * 3600) text = unit(1, 'day');
  else if (s < 30 * 86400) text = unit(Math.round(s / 86400), 'day');
  else return localDay(date, tz);
  return future ? `in ${text}` : `${text} ago`;
}

function bytes(n) {
  if (n === null || n === undefined || n === '') return EMPTY;
  const v = Number(n);
  if (!Number.isFinite(v) || v < 0) return EMPTY;
  if (v < 1024) return `${Math.round(v)} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let x = v / 1024;
  let i = 0;
  while (x >= 1024 && i < units.length - 1) {
    x /= 1024;
    i++;
  }
  const shown = x < 10 ? x.toFixed(1).replace(/\.0$/, '') : String(Math.round(x));
  return `${shown} ${units[i]}`;
}

function number(n) {
  const v = Number(n === null || n === undefined || n === '' ? 0 : n);
  return Number.isFinite(v) ? numberFormat.format(v) : EMPTY;
}

// Shortens to at most n characters (code points), ending with '…'.
function truncate(s, n = 80) {
  if (s === null || s === undefined) return '';
  const text = String(s);
  const chars = Array.from(text);
  if (chars.length <= n) return text;
  return chars.slice(0, Math.max(0, n - 1)).join('') + '…';
}

// The object exposed to views as `fmt`, bound to the relay's time zone and clock.
function createFormatter({ timezone = 'UTC', clock = systemClock } = {}) {
  return Object.freeze({
    dateTime: (d) => dateTime(d, timezone),
    date: (d) => date(d, timezone),
    relative: (d) => relative(d, clock.now(), timezone),
    bytes,
    number,
    truncate,
  });
}

module.exports = { createFormatter, dateTime, date, relative, bytes, number, truncate };
