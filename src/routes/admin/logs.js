'use strict';

// GET /admin/logs: the message log with filters and pagination. Rows never hold
// bodies or attachments (see repos/messages.js).

const express = require('express');
const { listApps } = require('../../repos/apps');
const { searchMessages } = require('../../repos/messages');
const { formField, parseId, parsePage } = require('../../services/appsAdmin');
const { isDayString } = require('../../lib/time');

const PAGE_SIZE = 50;
const STATUS_FILTERS = Object.freeze(['all', 'sent', 'failed', 'sending']);
const MAX_RECIPIENT_FILTER = 254;

function squash(s) {
  return String(s).replace(/\s+/g, ' ').trim().toLowerCase();
}

// An SMTP failure's error text usually quotes the server's reply already
// ("EENVELOPE: ... 550 5.1.1 ..."); the stored smtp_response is then shown only
// when it adds something.
function responseAddsToError(error, response) {
  if (!response) return false;
  if (!error) return true;
  const r = squash(response);
  return r !== '' && !squash(error).includes(r);
}

module.exports = function createLogsRouter(deps) {
  const router = express.Router();

  router.get('/logs', async (req, res) => {
    const query = req.query || {};
    const appId = parseId(formField(query, 'app').trim());
    const status = formField(query, 'status').trim();
    const from = formField(query, 'from').trim();
    const to = formField(query, 'to').trim();
    const filters = {
      app: appId === null ? '' : String(appId),
      status: STATUS_FILTERS.includes(status) ? status : 'all',
      from: isDayString(from) ? from : '',
      to: isDayString(to) ? to : '',
      recipient: formField(query, 'recipient').trim().slice(0, MAX_RECIPIENT_FILTER),
    };
    const page = parsePage(formField(query, 'page'));

    const [result, apps] = await Promise.all([
      searchMessages(deps.db, {
        appId: appId === null ? undefined : appId,
        status: filters.status,
        fromDay: filters.from || undefined,
        toDay: filters.to || undefined,
        recipient: filters.recipient || undefined,
        limit: PAGE_SIZE,
        offset: (page - 1) * PAGE_SIZE,
      }),
      listApps(deps.db),
    ]);

    // The filters to keep in pagination links (defaults left out).
    const linkQuery = {};
    for (const [k, v] of Object.entries(filters)) {
      if (v !== '' && !(k === 'status' && v === 'all')) linkQuery[k] = v;
    }

    res.render('logs', {
      title: 'Logs',
      activeNav: 'logs',
      rows: result.rows.map((m) => ({ ...m, showSmtpResponse: responseAddsToError(m.error, m.smtpResponse) })),
      total: result.total,
      page,
      pageSize: PAGE_SIZE,
      filters,
      statusFilters: STATUS_FILTERS,
      apps,
      linkQuery,
      filtered: Object.keys(linkQuery).length > 0,
      activeFilters: Object.keys(linkQuery).length,
    });
  });

  return router;
};

module.exports.responseAddsToError = responseAddsToError;
