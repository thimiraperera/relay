'use strict';

// One-time messages carried across a redirect in the session.
// req.flash(type, text) queues one; the next page that renders shows them all
// (res.locals.flash). Messages are consumed only when a page actually renders,
// so a redirect chain (e.g. via the login page) does not lose them.

const MAX_QUEUED = 10;

function flash(req, res, next) {
  req.flash = function addFlash(type, text) {
    if (!req.session) return;
    const list = Array.isArray(req.session.flash) ? req.session.flash : [];
    list.push({ type: String(type), text: String(text) });
    req.session.flash = list.slice(-MAX_QUEUED);
  };

  let consumed = null;
  Object.defineProperty(res.locals, 'flash', {
    configurable: true,
    enumerable: true,
    get() {
      if (consumed === null) {
        const list = req.session && Array.isArray(req.session.flash) ? req.session.flash : [];
        if (req.session && req.session.flash !== undefined) delete req.session.flash;
        consumed = list.filter((f) => f && typeof f.text === 'string');
      }
      return consumed;
    },
    set(value) {
      consumed = Array.isArray(value) ? value : [];
    },
  });
  next();
}

module.exports = { flash };
