'use strict';

// Configuration rules that tests elsewhere rely on (no database needed).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const h = require('./support/helpers');
const { ConfigError } = require('../src/config');

describe('configuration', () => {
  // Cleanup deletes messages after LOG_RETENTION_DAYS. An idempotency entry
  // whose message is gone counts as retryable, so a shorter retention than the
  // idempotency window would let a repeated message_id send twice.
  it('refuses LOG_RETENTION_DAYS shorter than IDEMPOTENCY_DAYS', () => {
    assert.throws(
      () => h.testConfig({ env: { LOG_RETENTION_DAYS: '2' } }),
      (err) => {
        assert.ok(err instanceof ConfigError);
        assert.ok(
          err.problems.some((p) => /LOG_RETENTION_DAYS \(2\).*IDEMPOTENCY_DAYS \(7\)/.test(p)),
          err.problems.join('; ')
        );
        return true;
      }
    );
    assert.throws(() => h.testConfig({ env: { LOG_RETENTION_DAYS: '6', IDEMPOTENCY_DAYS: '7' } }), ConfigError);
  });

  it('accepts a retention equal to the idempotency window', () => {
    const same = h.testConfig({ env: { LOG_RETENTION_DAYS: '7', IDEMPOTENCY_DAYS: '7' } });
    assert.equal(same.logRetentionDays, 7);
    const short = h.testConfig({ env: { LOG_RETENTION_DAYS: '2', IDEMPOTENCY_DAYS: '2' } });
    assert.equal(short.idempotencyDays, 2);
  });

  it('has the documented defaults the tests assume', () => {
    const config = h.testConfig();
    assert.equal(config.logRetentionDays, 90);
    assert.equal(config.idempotencyDays, 7);
    assert.equal(config.legacyMaxSkewSeconds, 300);
    assert.equal(config.staleSendingMs, 10 * 60 * 1000);
    assert.equal(config.smtpTimeoutMs, 30000);
    assert.ok(config.smtpSendDeadlineMs >= config.smtpTimeoutMs, 'the overall deadline is not shorter than one phase');
  });

  it('test overrides cannot build a configuration the relay would refuse', () => {
    assert.throws(() => h.testConfig({ logRetentionDays: 3 }), /logRetentionDays/);
  });
});
