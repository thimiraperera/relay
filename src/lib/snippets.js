'use strict';

// Copy-paste examples for the app page. They only interpolate the relay's base
// URL (quoted for each language) and a few numbers, never app settings such as
// the name: a quote or "?>" in a name must not break the snippet a site owner
// pastes into their code.

const PLACEHOLDER_KEY = 'YOUR_API_KEY';

// Shell: single-quoted, with embedded single quotes closed and re-opened.
function shQuote(s) {
  return "'" + String(s).replace(/'/g, "'\\''") + "'";
}

// PHP: single-quoted string literal.
function phpQuote(s) {
  return "'" + String(s).replace(/[\\']/g, (c) => '\\' + c) + "'";
}

// JavaScript: single-quoted string literal.
function jsQuote(s) {
  return "'" + String(s).replace(/[\\']/g, (c) => '\\' + c).replace(/\r/g, '\\r').replace(/\n/g, '\\n') + "'";
}

// A retry with the same message_id is safe, but one answer never clears: after an
// unknown SMTP outcome the id stays locked, because the server may have the email.
const UNKNOWN_1 = 'A 409 "message_id outcome unknown" (or a 502 ending in "(outcome unknown)") never clears:';
const UNKNOWN_2 = 'the email may already be delivered, so check before resending it under a new message_id.';

function lines(...parts) {
  return parts.join('\n') + '\n';
}

function minutes(seconds) {
  const m = Math.round(seconds / 60);
  return m === 1 ? '1 minute' : `${m} minutes`;
}

function days(n) {
  return n === 1 ? '1 day' : `${n} days`;
}

function apiSnippets(baseUrl, { idempotencyDays }) {
  const url = `${baseUrl}/v1/send`;
  const why = `message_id makes retries safe: Relay sends each message_id at most once (for ${days(idempotencyDays)}),`;
  const why2 = 'so resending after a timeout or a 5xx error cannot deliver the email twice.';

  const curl = lines(
    `# ${why}`,
    `# ${why2}`,
    `curl -sS --connect-timeout 10 --max-time 60 ${shQuote(url)} \\`,
    `  -H ${shQuote('Authorization: Bearer ' + PLACEHOLDER_KEY)} \\`,
    "  -H 'Content-Type: application/json' \\",
    "  --data-binary '{",
    '    "to": "recipient@example.com",',
    '    "subject": "Your order has shipped",',
    '    "html": "<p>Your order <b>#1234</b> is on its way.</p>",',
    '    "text": "Your order #1234 is on its way.",',
    '    "message_id": "order-1234-shipped"',
    "  }'",
    '# Success: HTTP 200 {"ok":true,"id":"msg_..."}. Failure: {"ok":false,"error":"..."}.',
    `# ${UNKNOWN_1}`,
    `# ${UNKNOWN_2}`,
    '# Optional fields: "cc", "bcc", "reply_to", and attachments (pdf, images, csv, txt, docx, xlsx):',
    '#   "attachments": [{"filename": "invoice.pdf", "content_base64": "JVBERi0xLjcK..."}]'
  );

  const php = lines(
    '<?php',
    '// Requires the PHP curl extension.',
    `// ${why}`,
    `// ${why2}`,
    `$apiKey = ${phpQuote(PLACEHOLDER_KEY)}; // keep the key out of version control`,
    '',
    '$payload = [',
    "    'to' => 'recipient@example.com',",
    "    'subject' => 'Your order has shipped',",
    "    'html' => '<p>Your order <b>#1234</b> is on its way.</p>',",
    "    'text' => 'Your order #1234 is on its way.',",
    "    'message_id' => 'order-1234-shipped',",
    '    // Optional attachments (pdf, images, csv, txt, docx, xlsx):',
    "    // 'attachments' => [[",
    "    //     'filename' => 'invoice.pdf',",
    "    //     'content_base64' => base64_encode(file_get_contents('/path/to/invoice.pdf')),",
    '    // ]],',
    '];',
    '$body = json_encode($payload);',
    'if ($body === false) {',
    "    throw new RuntimeException('Could not encode the message as JSON (invalid UTF-8?)');",
    '}',
    '',
    `$ch = curl_init(${phpQuote(url)});`,
    'curl_setopt_array($ch, [',
    '    CURLOPT_POST => true,',
    '    CURLOPT_HTTPHEADER => [',
    "        'Authorization: Bearer ' . $apiKey,",
    "        'Content-Type: application/json',",
    '    ],',
    '    CURLOPT_POSTFIELDS => $body,',
    '    CURLOPT_RETURNTRANSFER => true,',
    '    CURLOPT_CONNECTTIMEOUT => 10,',
    '    CURLOPT_TIMEOUT => 60,',
    ']);',
    '$response = curl_exec($ch);',
    '$status = curl_getinfo($ch, CURLINFO_HTTP_CODE);',
    '$curlError = curl_error($ch);',
    '',
    '$result = is_string($response) ? json_decode($response, true) : null;',
    "if ($status === 200 && is_array($result) && !empty($result['ok'])) {",
    "    // Sent. $result['id'] is the Relay message id (search for it in the Relay log).",
    '} else {',
    "    $reason = is_array($result) && isset($result['error']) ? $result['error'] : ($curlError ?: 'HTTP ' . $status);",
    "    error_log('Relay send failed: ' . $reason);",
    '    // Retry later with the same message_id; Relay will not send it twice.',
    `    // ${UNKNOWN_1}`,
    `    // ${UNKNOWN_2}`,
    '}'
  );

  const node = lines(
    '// Node.js 18+ (built-in fetch).',
    `// ${why}`,
    `// ${why2}`,
    `const RELAY_URL = ${jsQuote(url)};`,
    `const API_KEY = ${jsQuote(PLACEHOLDER_KEY)}; // better: process.env.RELAY_API_KEY`,
    '',
    'async function sendMail() {',
    '  const res = await fetch(RELAY_URL, {',
    "    method: 'POST',",
    '    headers: {',
    '      Authorization: `Bearer ${API_KEY}`,',
    "      'Content-Type': 'application/json',",
    '    },',
    '    body: JSON.stringify({',
    "      to: 'recipient@example.com',",
    "      subject: 'Your order has shipped',",
    "      html: '<p>Your order <b>#1234</b> is on its way.</p>',",
    "      text: 'Your order #1234 is on its way.',",
    "      message_id: 'order-1234-shipped',",
    '      // Optional attachments (pdf, images, csv, txt, docx, xlsx):',
    "      // attachments: [{ filename: 'invoice.pdf', content_base64: fs.readFileSync('invoice.pdf').toString('base64') }],",
    '    }),',
    '    signal: AbortSignal.timeout(60000),',
    '  });',
    '  const result = await res.json().catch(() => null);',
    '  if (res.status !== 200 || !result || result.ok !== true) {',
    "    throw new Error(`Relay send failed: ${(result && result.error) || 'HTTP ' + res.status}`);",
    '  }',
    '  return result.id; // Relay message id',
    '}',
    '',
    'sendMail().then(',
    "  (id) => console.log('sent', id),",
    '  // Retry later with the same message_id; Relay will not send it twice.',
    `  // ${UNKNOWN_1}`,
    `  // ${UNKNOWN_2}`,
    "  (err) => console.error(err.message)",
    ');'
  );

  return { curl, php, node };
}

function legacySnippets(baseUrl, { idempotencyDays, maxSkewSeconds }) {
  const url = `${baseUrl}/send.php`;
  const skew = minutes(maxSkewSeconds);
  const why = `message_id makes retries safe: Relay sends each message_id at most once (for ${days(idempotencyDays)}),`;
  const why2 = 'so resending after a timeout or a 5xx error cannot deliver the email twice.';
  const sign = 'The API key is the HMAC secret. Sign exactly the bytes you send: timestamp + "." + raw body.';
  const clock = `The timestamp must be within ${skew} of the relay's clock (keep the server clock in sync).`;

  const curl = lines(
    '# Legacy /send.php endpoint (HMAC-signed, one recipient per request).',
    `# ${sign}`,
    `# ${clock}`,
    `# ${why}`,
    `# ${why2}`,
    `API_KEY=${shQuote(PLACEHOLDER_KEY)}`,
    'BODY=\'{"message_id":"order-1234-shipped","to":"recipient@example.com","to_name":"Recipient Name","subject":"Your order has shipped","html":"<p>Your order <b>#1234</b> is on its way.</p>"}\'',
    'TS=$(date +%s)',
    "SIG=$(printf '%s' \"$TS.$BODY\" | openssl dgst -sha256 -hmac \"$API_KEY\" | awk '{print $NF}')",
    `curl -sS --connect-timeout 10 --max-time 60 ${shQuote(url)} \\`,
    "  -H 'Content-Type: application/json' \\",
    '  -H "X-Relay-Timestamp: $TS" \\',
    '  -H "X-Relay-Signature: sha256=$SIG" \\',
    '  --data-binary "$BODY"',
    '# Success: HTTP 200 {"ok":true}. Failure: {"error":"..."} with a 4xx/5xx status.',
    `# ${UNKNOWN_1}`,
    `# ${UNKNOWN_2}`
  );

  const php = lines(
    '<?php',
    '// Legacy /send.php endpoint (HMAC-signed, one recipient per request). Requires the curl extension.',
    `// ${sign}`,
    `// ${clock}`,
    `// ${why}`,
    `// ${why2}`,
    `$apiKey = ${phpQuote(PLACEHOLDER_KEY)}; // keep the key out of version control`,
    '',
    '$payload = [',
    "    'message_id' => 'order-1234-shipped',",
    "    'to' => 'recipient@example.com',",
    "    'to_name' => 'Recipient Name',",
    "    'subject' => 'Your order has shipped',",
    "    'html' => '<p>Your order <b>#1234</b> is on its way.</p>',",
    '    // Optional attachments (pdf, images, csv, txt, docx, xlsx):',
    "    // 'attachments' => [[",
    "    //     'filename' => 'invoice.pdf',",
    "    //     'content_type' => 'application/pdf',",
    "    //     'content_base64' => base64_encode(file_get_contents('/path/to/invoice.pdf')),",
    '    // ]],',
    '];',
    '$body = json_encode($payload);',
    'if ($body === false) {',
    "    throw new RuntimeException('Could not encode the message as JSON (invalid UTF-8?)');",
    '}',
    '$timestamp = (string) time();',
    "$signature = hash_hmac('sha256', $timestamp . '.' . $body, $apiKey);",
    '',
    `$ch = curl_init(${phpQuote(url)});`,
    'curl_setopt_array($ch, [',
    '    CURLOPT_POST => true,',
    '    CURLOPT_HTTPHEADER => [',
    "        'Content-Type: application/json',",
    "        'X-Relay-Timestamp: ' . $timestamp,",
    "        'X-Relay-Signature: sha256=' . $signature,",
    '    ],',
    '    CURLOPT_POSTFIELDS => $body, // the exact string that was signed',
    '    CURLOPT_RETURNTRANSFER => true,',
    '    CURLOPT_CONNECTTIMEOUT => 10,',
    '    CURLOPT_TIMEOUT => 60,',
    ']);',
    '$response = curl_exec($ch);',
    '$status = curl_getinfo($ch, CURLINFO_HTTP_CODE);',
    '$curlError = curl_error($ch);',
    '',
    '$result = is_string($response) ? json_decode($response, true) : null;',
    "if ($status === 200 && is_array($result) && !empty($result['ok'])) {",
    '    // Sent.',
    '} else {',
    "    $reason = is_array($result) && isset($result['error']) ? $result['error'] : ($curlError ?: 'HTTP ' . $status);",
    "    error_log('Relay send failed: ' . $reason);",
    '    // Retry later with the same message_id (and a fresh timestamp and signature).',
    `    // ${UNKNOWN_1}`,
    `    // ${UNKNOWN_2}`,
    '}'
  );

  const node = lines(
    '// Legacy /send.php endpoint (HMAC-signed, one recipient per request). Node.js 18+.',
    `// ${sign}`,
    `// ${clock}`,
    `// ${why}`,
    `// ${why2}`,
    "const crypto = require('node:crypto');",
    '',
    `const RELAY_URL = ${jsQuote(url)};`,
    `const API_KEY = ${jsQuote(PLACEHOLDER_KEY)}; // better: process.env.RELAY_API_KEY`,
    '',
    'async function sendMail() {',
    '  const body = JSON.stringify({',
    "    message_id: 'order-1234-shipped',",
    "    to: 'recipient@example.com',",
    "    to_name: 'Recipient Name',",
    "    subject: 'Your order has shipped',",
    "    html: '<p>Your order <b>#1234</b> is on its way.</p>',",
    '  });',
    '  const timestamp = String(Math.floor(Date.now() / 1000));',
    "  const signature = crypto.createHmac('sha256', API_KEY).update(`${timestamp}.${body}`).digest('hex');",
    '  const res = await fetch(RELAY_URL, {',
    "    method: 'POST',",
    '    headers: {',
    "      'Content-Type': 'application/json',",
    "      'X-Relay-Timestamp': timestamp,",
    "      'X-Relay-Signature': `sha256=${signature}`,",
    '    },',
    '    body, // the exact string that was signed',
    '    signal: AbortSignal.timeout(60000),',
    '  });',
    '  const result = await res.json().catch(() => null);',
    '  if (res.status !== 200 || !result || result.ok !== true) {',
    "    throw new Error(`Relay send failed: ${(result && result.error) || 'HTTP ' + res.status}`);",
    '  }',
    '}',
    '',
    'sendMail().then(',
    "  () => console.log('sent'),",
    '  // Retry later with the same message_id (a fresh timestamp and signature are made each time).',
    `  // ${UNKNOWN_1}`,
    `  // ${UNKNOWN_2}`,
    "  (err) => console.error(err.message)",
    ');'
  );

  return { curl, php, node };
}

// Returns { curl, php, node } for the app's endpoint: /v1/send with a Bearer key,
// or /send.php with an HMAC signature when the app uses legacy signing.
function buildSnippets({ baseUrl, app, idempotencyDays = 7, maxSkewSeconds = 300 }) {
  const base = String(baseUrl || '').replace(/\/+$/, '');
  const opts = { idempotencyDays, maxSkewSeconds };
  return app && app.legacySigning ? legacySnippets(base, opts) : apiSnippets(base, opts);
}

module.exports = { buildSnippets, PLACEHOLDER_KEY };
