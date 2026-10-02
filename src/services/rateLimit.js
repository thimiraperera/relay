'use strict';

// Fixed-window rate limits stored in rate_counters, so every Node process (and
// every cPanel worker) shares the same counts. Each window gets its own row
// (`<key>:<windowId>`), which expires one window after the window ends.

const { sha256Hex } = require('../lib/crypto');
const { localDay, localDateTime } = require('../lib/time');
const { incrementCounter, getCounter } = require('../repos/rateCounters');

const MAX_KEY_LENGTH = 191;
const DAY_MS = 24 * 60 * 60 * 1000;

function counterKey(key, windowId) {
  const k = `${key}:${windowId}`;
  return k.length > MAX_KEY_LENGTH ? `${sha256Hex(String(key)).slice(0, 40)}:${windowId}` : k;
}

function windowInfo(deps, windowSeconds) {
  const nowMs = deps.clock.now().getTime();
  const windowMs = windowSeconds * 1000;
  const windowId = Math.floor(nowMs / windowMs);
  const windowEndMs = (windowId + 1) * windowMs;
  return {
    windowId,
    expiresAt: new Date(windowEndMs + windowMs),
    retryAfterSeconds: Math.max(1, Math.ceil((windowEndMs - nowMs) / 1000)),
  };
}

// Counts this hit; allowed while count <= limit.
async function hitWindow(deps, key, limit, windowSeconds) {
  const w = windowInfo(deps, windowSeconds);
  const count = await incrementCounter(deps.db, counterKey(key, w.windowId), w.expiresAt);
  return { allowed: count <= limit, count, retryAfterSeconds: w.retryAfterSeconds };
}

// Reads the current window without counting. `count` is the hits recorded so
// far; `allowed` says whether one more hit would still be within the limit
// (i.e. count < limit), matching what hitWindow would answer for that hit.
async function peekWindow(deps, key, limit, windowSeconds) {
  const w = windowInfo(deps, windowSeconds);
  const count = await getCounter(deps.db, counterKey(key, w.windowId));
  return { allowed: count < limit, count, retryAfterSeconds: w.retryAfterSeconds };
}

function secondsToLocalMidnight(now, tz) {
  const [, time] = localDateTime(now, tz).split(' ');
  const [h, m, s] = time.split(':').map(Number);
  return 24 * 3600 - (h * 3600 + m * 60 + s);
}

// Calendar-day window in config.timezone (resets at local midnight).
async function hitDaily(deps, key, limit) {
  const now = deps.clock.now();
  const tz = deps.config.timezone;
  const day = localDay(now, tz);
  const count = await incrementCounter(deps.db, counterKey(key, `d:${day}`), new Date(now.getTime() + 2 * DAY_MS));
  return {
    allowed: count <= limit,
    count,
    retryAfterSeconds: Math.max(60, secondsToLocalMidnight(now, tz)),
  };
}

module.exports = { hitWindow, peekWindow, hitDaily, counterKey };
