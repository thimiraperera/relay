'use strict';

// Attachment rules: the type comes from the file extension and
// is verified by sniffing the content; the caller's content_type is advisory;
// html + text + attachments together count toward the app's size limit.

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const h = require('./support/helpers');
const { normalizeAttachments, totalAttachmentBytes, ALLOWED_EXTENSIONS } = require('../src/lib/attachments');

const T = { timeout: 60000 };
const MAX = 1024 * 1024;
// Every attachment is charged its decoded bytes plus this much MIME overhead
// plus 6 bytes per UTF-8 byte of its filename.
const PART_OVERHEAD = 1024;
const nameCharge = (filename) => 6 * Buffer.byteLength(filename, 'utf8');
const charge = (bytes, filename) => bytes + PART_OVERHEAD + nameCharge(filename);
// A Sinhala filename: 8 characters of 3 UTF-8 bytes each + ".pdf" = 28 bytes.
const SINHALA_NAME = 'අයදුම්පත.pdf';

const latin1 = (s) => Buffer.from(s, 'latin1');
const PDF = latin1('%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<<>>\n%%EOF\n');
const JPEG = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0xff, 0xd9]);
const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d, 0x49, 0x48, 0x44, 0x52]);
const GIF89 = latin1('GIF89a\x01\x00\x01\x00\x80\x00\x00;');
const GIF87 = latin1('GIF87a\x01\x00\x01\x00\x80\x00\x00;');
const WEBP = Buffer.concat([latin1('RIFF'), Buffer.from([0x24, 0, 0, 0]), latin1('WEBPVP8 '), Buffer.alloc(8)]);
const heif = (brand) => Buffer.concat([Buffer.from([0, 0, 0, 0x18]), latin1('ftyp' + brand), Buffer.alloc(4), latin1('mif1heic')]);
const BMP = Buffer.concat([latin1('BM'), Buffer.alloc(24)]);
const TIFF_LE = Buffer.from([0x49, 0x49, 0x2a, 0x00, 0x08, 0, 0, 0]);
const TIFF_BE = Buffer.from([0x4d, 0x4d, 0x00, 0x2a, 0, 0, 0, 0x08]);
const ZIP = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x14, 0, 0, 0]), latin1('[Content_Types].xml')]);
const CSV = Buffer.from('name,amount\nNimal,1200\n', 'utf8');
const TXT = Buffer.from('Plain text attachment\r\n', 'utf8');

// Every allowed extension with real leading bytes and the
// canonical content type the relay must use.
const ALLOWED = {
  pdf: [PDF, 'application/pdf'],
  jpg: [JPEG, 'image/jpeg'],
  jpeg: [JPEG, 'image/jpeg'],
  png: [PNG, 'image/png'],
  gif: [GIF89, 'image/gif'],
  webp: [WEBP, 'image/webp'],
  heic: [heif('heic'), 'image/heic'],
  heif: [heif('mif1'), 'image/heif'],
  bmp: [BMP, 'image/bmp'],
  tif: [TIFF_LE, 'image/tiff'],
  tiff: [TIFF_BE, 'image/tiff'],
  csv: [CSV, 'text/csv'],
  txt: [TXT, 'text/plain'],
  docx: [ZIP, 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
  xlsx: [ZIP, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
};

function att(filename, content, contentType) {
  const item = { filename, content_base64: h.b64(content) };
  if (contentType !== undefined) item.content_type = contentType;
  return item;
}

function normalize(list, maxBytes = MAX) {
  return normalizeAttachments(list, { maxBytes });
}

function throwsHttp(fn, status, message) {
  assert.throws(fn, (err) => {
    assert.equal(err.status, status, `status of "${err.message}"`);
    assert.equal(err.message, message);
    return true;
  });
}

describe('normalizeAttachments', () => {
  it('allows exactly the documented file types', () => {
    assert.deepEqual([...ALLOWED_EXTENSIONS].sort(), Object.keys(ALLOWED).sort());
  });

  for (const [ext, [content, contentType]] of Object.entries(ALLOWED)) {
    it(`accepts a real .${ext} file as ${contentType}`, () => {
      const [out] = normalize([att(`file.${ext}`, content, 'application/octet-stream')]);
      assert.equal(out.filename, `file.${ext}`);
      assert.equal(out.contentType, contentType);
      assert.deepEqual(out.content, content);
    });

    it(`refuses .${ext} content that does not match the type`, () => {
      const wrong = ext === 'csv' || ext === 'txt' ? Buffer.from('MZ\x90\x00\x03\x00\x00\x00', 'latin1') : latin1('just some text');
      throwsHttp(() => normalize([att(`file.${ext}`, wrong)]), 400, 'attachment content does not match file type');
    });
  }

  it('matches extensions case-insensitively and accepts GIF87a and other HEIF brands', () => {
    assert.equal(normalize([att('PHOTO.JPG', JPEG)])[0].contentType, 'image/jpeg');
    assert.equal(normalize([att('old.gif', GIF87)])[0].contentType, 'image/gif');
    for (const brand of ['heix', 'hevc', 'hevx', 'heim', 'heis', 'msf1']) {
      assert.equal(normalize([att('p.heic', heif(brand))])[0].contentType, 'image/heic', brand);
    }
    throwsHttp(() => normalize([att('p.heic', heif('avif'))]), 400, 'attachment content does not match file type');
  });

  for (const ext of ['exe', 'svg', 'html', 'js', 'zip']) {
    it(`refuses .${ext} files`, () => {
      throwsHttp(() => normalize([att(`evil.${ext}`, PDF)]), 400, `attachment type not allowed: ${ext}`);
    });
  }

  it('refuses an svg even when content_type claims an image', () => {
    const svg = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>');
    throwsHttp(() => normalize([att('logo.svg', svg, 'image/svg+xml')]), 400, 'attachment type not allowed: svg');
  });

  it('ignores the caller content_type', () => {
    const [pdf] = normalize([att('a.pdf', PDF, 'image/png')]);
    assert.equal(pdf.contentType, 'application/pdf');
    const [png] = normalize([att('a.png', PNG, 'application/x-msdownload')]);
    assert.equal(png.contentType, 'image/png');
    const [noType] = normalize([att('a.png', PNG, null)]);
    assert.equal(noType.contentType, 'image/png');
    // A real PDF named .png is still refused: the extension decides the type.
    throwsHttp(() => normalize([att('a.png', PDF, 'application/pdf')]), 400, 'attachment content does not match file type');
  });

  it('finds the PDF header within the first 1024 bytes only', () => {
    const at100 = Buffer.concat([Buffer.alloc(100, 0x20), PDF]);
    assert.equal(normalize([att('late.pdf', at100)])[0].contentType, 'application/pdf');
    const at1100 = Buffer.concat([Buffer.alloc(1100, 0x20), PDF]);
    throwsHttp(() => normalize([att('later.pdf', at1100)]), 400, 'attachment content does not match file type');
  });

  it('accepts UTF-16 csv/txt (BOM first) but not other text with NUL bytes', () => {
    const utf16le = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('a,b\r\n1,2\r\n', 'utf16le')]);
    assert.equal(normalize([att('data.csv', utf16le)])[0].contentType, 'text/csv');
    const utf16be = Buffer.concat([Buffer.from([0xfe, 0xff]), Buffer.from('hi', 'utf16le').swap16()]);
    assert.equal(normalize([att('note.txt', utf16be)])[0].contentType, 'text/plain');
    const nul = Buffer.from('a,b\u0000\n', 'utf8');
    throwsHttp(() => normalize([att('data.csv', nul)]), 400, 'attachment content does not match file type');
  });

  it('refuses invalid base64', () => {
    for (const bad of ['abc', 'ab$=', '====', 'YWJj=YWJj', 'YQ===']) {
      throwsHttp(
        () => normalize([{ filename: 'a.txt', content_base64: bad }]),
        400,
        'attachment is not valid base64'
      );
    }
  });

  it('accepts line-wrapped base64', () => {
    const wrapped = h.b64(PDF).replace(/(.{20})/g, '$1\r\n');
    assert.deepEqual(normalize([{ filename: 'a.pdf', content_base64: wrapped }])[0].content, PDF);
  });

  it('refuses an empty attachment', () => {
    throwsHttp(() => normalize([{ filename: 'empty.txt', content_base64: '' }]), 400, 'attachment is empty');
  });

  it('validates the list and each item', () => {
    assert.deepEqual(normalize(undefined), []);
    assert.deepEqual(normalize(null), []);
    throwsHttp(() => normalize('a.pdf'), 400, 'attachments must be an array');
    throwsHttp(() => normalize({ filename: 'a.pdf' }), 400, 'attachments must be an array');
    for (const bad of [
      null,
      'a.pdf',
      { content_base64: h.b64(PDF) },
      { filename: 'a.pdf' },
      { filename: 7, content_base64: h.b64(PDF) },
      { filename: 'a.pdf', content_base64: h.b64(PDF), content_type: 5 },
    ]) {
      throwsHttp(() => normalize([bad]), 400, 'invalid attachment');
    }
  });

  it('cleans filenames: no path, no line breaks, 1-200 characters', () => {
    assert.equal(normalize([att('../../etc/report.pdf', PDF)])[0].filename, 'report.pdf');
    assert.equal(normalize([att('C:\\Users\\x\\report.pdf', PDF)])[0].filename, 'report.pdf');
    assert.equal(normalize([att('my\r\nreport.pdf', PDF)])[0].filename, 'my report.pdf');
    throwsHttp(() => normalize([att('', PDF)]), 400, 'invalid attachment filename');
    throwsHttp(() => normalize([att('dir/', PDF)]), 400, 'invalid attachment filename');
    throwsHttp(() => normalize([att('x'.repeat(197) + '.pdf', PDF)]), 400, 'invalid attachment filename');
    assert.equal(normalize([att('x'.repeat(196) + '.pdf', PDF)])[0].filename.length, 200);
  });

  it('truncates a long extension in the error message', () => {
    throwsHttp(() => normalize([att('a.' + 'x'.repeat(30), PDF)]), 400, 'attachment type not allowed: xxxxxxxxxx');
  });

  it('answers 413 before decoding an oversized attachment', () => {
    const big = { filename: 'big.pdf', content_base64: 'A'.repeat(Math.ceil((1000 * 4) / 3) + 8) };
    throwsHttp(() => normalize([big], 1000), 413, 'message too large');
  });

  it('counts the decoded bytes of all attachments plus the per-part and filename charge', () => {
    const list = normalize([att('a.pdf', PDF), att('b.png', PNG)]);
    // 'a.pdf' and 'b.png' are 5 bytes each: 30 bytes of filename charge apiece.
    assert.equal(totalAttachmentBytes(list), PDF.length + PNG.length + 2 * PART_OVERHEAD + 2 * 30);
    assert.equal(totalAttachmentBytes(list), charge(PDF.length, 'a.pdf') + charge(PNG.length, 'b.png'));
  });

  it('charges the per-part overhead and the filename in the running total too', () => {
    const one = [att('a.txt', Buffer.from('x'))];
    const exact = 1 + PART_OVERHEAD + 30;
    throwsHttp(() => normalize(one, exact - 1), 413, 'message too large');
    assert.equal(normalize(one, exact).length, 1);
    // Many tiny parts cannot slip under the limit ('t0.txt': 6 bytes, 36 charged).
    const tiny = Array.from({ length: 10 }, (_, i) => att(`t${i}.txt`, Buffer.from('x')));
    const tenParts = 10 * (1 + PART_OVERHEAD + 36);
    throwsHttp(() => normalize(tiny, tenParts - 1), 413, 'message too large');
    assert.equal(normalize(tiny, tenParts).length, 10);
    assert.equal(totalAttachmentBytes(normalize(tiny, tenParts)), tenParts);
  });

  it('charges a non-ASCII filename by its UTF-8 bytes, six times', () => {
    assert.equal(Buffer.byteLength(SINHALA_NAME, 'utf8'), 28);
    const exact = PDF.length + PART_OVERHEAD + 6 * 28;
    throwsHttp(() => normalize([att(SINHALA_NAME, PDF)], exact - 1), 413, 'message too large');
    const list = normalize([att(SINHALA_NAME, PDF)], exact);
    assert.equal(list[0].filename, SINHALA_NAME);
    assert.equal(totalAttachmentBytes(list), exact);
    // The longest allowed name, 200 characters of 3 bytes: 3,600 bytes of charge,
    // well over the fixed 1024 that used to be assumed to cover it.
    const longName = '\u0D85'.repeat(196) + '.pdf';
    const long = normalize([att(longName, PDF)]);
    assert.equal(totalAttachmentBytes(long), PDF.length + PART_OVERHEAD + 6 * (196 * 3 + 4));
  });

  it('charges the filename as cleaned (path and line breaks removed)', () => {
    const [cleaned] = normalize([att('C:\\Users\\x\\report.pdf', PDF)]);
    assert.equal(totalAttachmentBytes([cleaned]), charge(PDF.length, 'report.pdf'));
  });
});

describe('request body limit (config)', () => {
  // The body limit must leave room for the worst realistic encoding of a
  // message at MAX_MESSAGE_BYTES: base64 (4/3), PHP chunk_split line breaks
  // (CRLF per 76 characters, JSON-escaped to 4 characters), PHP's escaped
  // slashes (about 1 in 64 base64 characters) and the JSON envelope.
  for (const maxBytes of [1024, 10 * 1024 * 1024, 25 * 1024 * 1024]) {
    it(`leaves room for a PHP-encoded ${maxBytes}-byte message`, () => {
      const config = h.testConfig({ env: { MAX_MESSAGE_BYTES: String(maxBytes) } });
      assert.equal(config.maxMessageBytes, maxBytes);
      const worstCase = Math.ceil(((maxBytes * 4) / 3) * (1 + 4 / 76 + 1 / 64)) + 64 * 1024;
      assert.ok(config.bodyLimitBytes >= worstCase, `${config.bodyLimitBytes} < ${worstCase}`);
    });
  }
});

describe('attachments over HTTP', () => {
  let deps;
  let smtp;
  let httpApp;

  before(async () => {
    if (!h.dbAvailable()) return;
    smtp = await h.startSmtpServer();
    deps = h.createTestDeps({ clock: h.createFakeClock() });
    httpApp = h.createHttpApp(deps);
  });

  after(async () => {
    if (smtp) await smtp.close();
    if (deps) await deps.db.close();
  });

  // subject 'S' + html '<p>x</p>' + text 'x' = 10 bytes before attachments.
  function sized(to, attachments) {
    return { to, subject: 'S', html: '<p>x</p>', text: 'x', attachments };
  }

  it('delivers attachments with the canonical content type', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { key } = await h.insertTestApp(deps, { smtp });
    const to = h.uniqueEmail();
    const res = await h.postV1(httpApp, key, {
      to,
      subject: 'Statement',
      html: '<p>Attached.</p>',
      attachments: [att('statement.pdf', PDF, 'application/octet-stream'), att('chart.png', PNG)],
    });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    const [msg] = smtp.messagesTo(to);
    const files = msg.parsed.attachments.map((a) => [a.filename, a.contentType, a.content.equals(a.filename.endsWith('pdf') ? PDF : PNG)]);
    assert.deepEqual(files, [
      ['statement.pdf', 'application/pdf', true],
      ['chart.png', 'image/png', true],
    ]);
  });

  it('answers 400 for a disallowed type and delivers nothing', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { app, key } = await h.insertTestApp(deps, { smtp });
    const to = h.uniqueEmail();
    const exe = att('setup.exe', Buffer.from('MZ\x90\x00', 'latin1'));
    const res = await h.postV1(httpApp, key, sized(to, [exe]));
    assert.equal(res.status, 400);
    assert.deepEqual(res.body, { ok: false, error: 'attachment type not allowed: exe' });
    assert.equal(smtp.messagesTo(to).length, 0);
    const last = (await h.listMessages(deps, app.id)).at(-1);
    assert.equal(last.status, 'rejected');
    assert.equal(last.httpStatus, 400);
    // The rejected row's size estimate charges the attachment like a real one:
    // 3/4 of its base64 length + the part overhead + 6 per filename byte.
    const estimate = 10 + Math.floor((exe.content_base64.length * 3) / 4) + PART_OVERHEAD + nameCharge('setup.exe');
    assert.equal(last.sizeBytes, estimate);
  });

  it('answers 413 over the app size limit, counting exactly up to the limit', T, async (t) => {
    if (!h.requireDb(t)) return;
    const limit = 50000;
    const { app, key } = await h.insertTestApp(deps, { smtp, maxMessageBytes: limit });
    const pdfOf = (size) => Buffer.concat([PDF, Buffer.alloc(size - PDF.length, 0x20)]);
    // 10 bytes of subject/html/text, one attachment: its bytes + PART_OVERHEAD +
    // 6 per filename byte ('fits.pdf' and 'over.pdf' are both 8 bytes).
    const room = limit - 10 - PART_OVERHEAD - nameCharge('fits.pdf');

    const toOk = h.uniqueEmail();
    const atLimit = await h.postV1(httpApp, key, sized(toOk, [att('fits.pdf', pdfOf(room))]));
    assert.equal(atLimit.status, 200, JSON.stringify(atLimit.body));
    assert.equal(smtp.messagesTo(toOk).length, 1);
    const fitsRow = (await h.listMessages(deps, app.id)).find((r) => r.publicId === atLimit.body.id);
    assert.equal(fitsRow.sizeBytes, limit, 'size_bytes stores the charged size');

    const toBig = h.uniqueEmail();
    const over = await h.postV1(httpApp, key, sized(toBig, [att('over.pdf', pdfOf(room + 1))]));
    assert.equal(over.status, 413);
    assert.deepEqual(over.body, { ok: false, error: 'message too large' });

    const toBigger = h.uniqueEmail();
    const wayOver = await h.postV1(httpApp, key, sized(toBigger, [att('huge.pdf', pdfOf(limit * 3))]));
    assert.equal(wayOver.status, 413);
    assert.deepEqual(wayOver.body, { ok: false, error: 'message too large' });

    assert.equal(smtp.messagesTo(toBig).length + smtp.messagesTo(toBigger).length, 0);
    const rejected = (await h.listMessages(deps, app.id)).filter((r) => r.status === 'rejected');
    assert.equal(rejected.length, 2);
    assert.ok(rejected.every((r) => r.httpStatus === 413 && r.error === 'message too large'));
  });

  it('splits the size limit across several attachments', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { key } = await h.insertTestApp(deps, { smtp, maxMessageBytes: 4000 });
    const part = Buffer.concat([PDF, Buffer.alloc(2000 - PDF.length, 0x20)]);
    const to = h.uniqueEmail();
    const res = await h.postV1(httpApp, key, sized(to, [att('a.pdf', part), att('b.pdf', part)]));
    assert.equal(res.status, 413);
    assert.deepEqual(res.body, { ok: false, error: 'message too large' });
  });

  it('charges every attachment its MIME overhead, so many tiny parts cannot pass', T, async (t) => {
    if (!h.requireDb(t)) return;
    const limit = 5000;
    const { key } = await h.insertTestApp(deps, { smtp, maxMessageBytes: limit });
    const tiny = (n) => Array.from({ length: n }, (_, i) => att(`part${i}.txt`, Buffer.from('a')));
    // 10 + n * (1 + 1024 + 6 * 9): 4 parts = 4326 bytes, 5 parts = 5405 bytes.
    const toOk = h.uniqueEmail();
    const four = await h.postV1(httpApp, key, sized(toOk, tiny(4)));
    assert.equal(four.status, 200, JSON.stringify(four.body));
    assert.equal(smtp.messagesTo(toOk)[0].parsed.attachments.length, 4);
    const toOver = h.uniqueEmail();
    const five = await h.postV1(httpApp, key, sized(toOver, tiny(5)));
    assert.equal(five.status, 413);
    assert.deepEqual(five.body, { ok: false, error: 'message too large' });
    assert.equal(smtp.messagesTo(toOver).length, 0);
  });

  it('charges a non-ASCII filename by its UTF-8 bytes, exactly up to the limit', T, async (t) => {
    if (!h.requireDb(t)) return;
    const limit = 6000;
    const { app, key } = await h.insertTestApp(deps, { smtp, maxMessageBytes: limit });
    const pdfOf = (size) => Buffer.concat([PDF, Buffer.alloc(size - PDF.length, 0x20)]);
    // 10 bytes of subject/html/text + attachment bytes + 1024 + 6 * 28.
    const room = limit - 10 - PART_OVERHEAD - nameCharge(SINHALA_NAME);
    assert.equal(room, limit - 10 - 1024 - 168);

    const toOk = h.uniqueEmail();
    const fits = await h.postV1(httpApp, key, sized(toOk, [att(SINHALA_NAME, pdfOf(room))]));
    assert.equal(fits.status, 200, JSON.stringify(fits.body));
    const [msg] = smtp.messagesTo(toOk);
    assert.equal(msg.parsed.attachments[0].filename, SINHALA_NAME, 'the name arrives intact');
    assert.equal(msg.parsed.attachments[0].size, room);
    const row = (await h.listMessages(deps, app.id)).find((r) => r.publicId === fits.body.id);
    assert.equal(row.sizeBytes, limit, 'size_bytes stores the charged size');

    const toOver = h.uniqueEmail();
    const over = await h.postV1(httpApp, key, sized(toOver, [att(SINHALA_NAME, pdfOf(room + 1))]));
    assert.equal(over.status, 413);
    assert.deepEqual(over.body, { ok: false, error: 'message too large' });
    assert.equal(smtp.messagesTo(toOver).length, 0);
  });

  it('counts display names toward the size limit', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { key } = await h.insertTestApp(deps, { smtp, maxMessageBytes: 2000 });
    // subject 1 + text 1000 = 1001 bytes; the recipient's name fills the rest.
    const body = (to, nameLength) => ({ to: `"${'N'.repeat(nameLength)}" <${to}>`, subject: 'S', text: 't'.repeat(1000) });
    const toOk = h.uniqueEmail();
    const fits = await h.postV1(httpApp, key, body(toOk, 999));
    assert.equal(fits.status, 200, JSON.stringify(fits.body));
    const toOver = h.uniqueEmail();
    const over = await h.postV1(httpApp, key, body(toOver, 1000));
    assert.equal(over.status, 413);
    assert.deepEqual(over.body, { ok: false, error: 'message too large' });
    assert.equal(smtp.messagesTo(toOver).length, 0);
  });

  it('counts html and text toward the size limit', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { key } = await h.insertTestApp(deps, { smtp, maxMessageBytes: 2000 });
    const html = '<p>' + 'h'.repeat(1193) + '</p>'; // 1200 bytes
    const toOver = h.uniqueEmail();
    const over = await h.postV1(httpApp, key, { to: toOver, subject: 'S', html, text: 't'.repeat(800) });
    assert.equal(over.status, 413);
    assert.deepEqual(over.body, { ok: false, error: 'message too large' });

    const toOk = h.uniqueEmail();
    const ok = await h.postV1(httpApp, key, { to: toOk, subject: 'S', html, text: 't'.repeat(799) });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));

    const toAtt = h.uniqueEmail();
    const withAttachment = await h.postV1(httpApp, key, {
      to: toAtt,
      subject: 'S',
      html,
      attachments: [att('note.txt', Buffer.alloc(800, 0x61))],
    });
    assert.equal(withAttachment.status, 413);
    assert.equal(smtp.messagesTo(toOver).length + smtp.messagesTo(toAtt).length, 0);
  });

  it('counts multi-byte characters by their UTF-8 size', T, async (t) => {
    if (!h.requireDb(t)) return;
    const { key } = await h.insertTestApp(deps, { smtp, maxMessageBytes: 1500 });
    // 600 characters, 1800 UTF-8 bytes.
    const res = await h.postV1(httpApp, key, { to: h.uniqueEmail(), subject: 'S', text: 'අ'.repeat(600) });
    assert.equal(res.status, 413);
    assert.deepEqual(res.body, { ok: false, error: 'message too large' });
  });
});

// A message just under the default MAX_MESSAGE_BYTES (10 MiB) must fit the
// default request body limit on both endpoints, also in the bulkiest encoding a
// PHP client produces. About 14-15 MB per request; each case runs alone.
describe('near-limit messages with the default limits', () => {
  let deps;
  let smtp;
  let httpApp;
  const BIG = { timeout: 120000 };

  before(async () => {
    if (!h.dbAvailable()) return;
    smtp = await h.startSmtpServer();
    deps = h.createTestDeps({ clock: h.createFakeClock() });
    httpApp = h.createHttpApp(deps);
  });

  after(async () => {
    if (smtp) await smtp.close();
    if (deps) await deps.db.close();
  });

  // A PDF of exactly `size` bytes; random content gives base64 a realistic
  // share of "/" characters (which PHP escapes).
  function bigPdf(size) {
    const head = Buffer.from('%PDF-1.4\n', 'latin1');
    const tail = Buffer.from('\n%%EOF\n', 'latin1');
    return Buffer.concat([head, crypto.randomBytes(size - head.length - tail.length), tail]);
  }

  it('accepts a message just under the limit on /v1/send', BIG, async (t) => {
    if (!h.requireDb(t)) return;
    assert.equal(deps.config.maxMessageBytes, 10 * 1024 * 1024, 'default MAX_MESSAGE_BYTES');
    const { key } = await h.insertTestApp(deps, { smtp });
    const subject = 'Statement near the limit';
    const text = 'Your statement is attached.';
    // Room for a text part the relay might add, and some slack.
    const size =
      deps.config.maxMessageBytes -
      Buffer.byteLength(subject) -
      2 * Buffer.byteLength(text) -
      PART_OVERHEAD -
      nameCharge('statement.pdf') -
      64;
    const to = h.uniqueEmail();
    const res = await h.postV1(
      httpApp,
      key,
      { to, subject, text, attachments: [{ filename: 'statement.pdf', content_base64: bigPdf(size).toString('base64') }] },
      { 'X-Forwarded-For': h.uniqueIp() }
    );
    assert.equal(res.status, 200, JSON.stringify(res.body));
    const delivered = smtp.messagesTo(to);
    assert.equal(delivered.length, 1);
    assert.equal(delivered[0].parsed.attachments[0].size, size);
    delivered[0].parsed.attachments = [];
    delivered[0].raw = Buffer.alloc(0);
  });

  it('accepts it on /send.php as PHP sends it (chunk_split base64, escaped slashes)', BIG, async (t) => {
    if (!h.requireDb(t)) return;
    const legacy = await h.insertTestApp(deps, { smtp, legacySigning: true });
    const fields = { subject: 'Account application', html: '<p>Your application form is attached.</p>', to_name: 'Applicant' };
    const textBytes = Object.values(fields).reduce((n, s) => n + Buffer.byteLength(s), 0);
    const size = deps.config.maxMessageBytes - textBytes - PART_OVERHEAD - nameCharge('application.pdf') - 64;
    const to = h.uniqueEmail();
    // chunk_split(base64_encode($pdf)): CRLF after every 76 characters.
    const chunked = bigPdf(size).toString('base64').replace(/.{76}/g, '$&\r\n');
    const backslash = String.fromCharCode(92);
    const raw = JSON.stringify({
      message_id: h.uniqueName('big'),
      to,
      ...fields,
      attachments: [{ filename: 'application.pdf', content_type: 'application/pdf', content_base64: chunked }],
    })
      .split('/')
      .join(backslash + '/');
    assert.ok(raw.length > 14 * 1000 * 1000 && raw.length < deps.config.bodyLimitBytes, `body of ${raw.length} bytes`);

    const res = await h.postLegacy(httpApp, deps, legacy.key, raw, { headers: { 'X-Forwarded-For': h.uniqueIp() } });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.deepEqual(res.body, { ok: true });
    const delivered = smtp.messagesTo(to);
    assert.equal(delivered.length, 1);
    assert.equal(delivered[0].parsed.attachments[0].size, size);
    delivered[0].parsed.attachments = [];
    delivered[0].raw = Buffer.alloc(0);
  });
});
