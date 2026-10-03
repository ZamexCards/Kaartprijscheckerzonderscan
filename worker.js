/* ZamexCards beveiligde kaartscanner - Cloudflare Worker
 * Geheimen: OPENAI_API_KEY en SCANNER_PIN
 * Variabelen: ALLOWED_ORIGIN en optioneel OPENAI_MODEL
 */

const recentRequests = new Map();
const MAX_IMAGE_CHARS = 7_000_000;

function cors(origin, allowed) {
  return {
    'Access-Control-Allow-Origin': origin === allowed ? origin : allowed,
    'Access-Control-Allow-Methods': 'POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,X-Scanner-Pin',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  };
}

function json(data, status, headers) {
  return new Response(JSON.stringify(data), { status, headers: { ...headers, 'Content-Type': 'application/json;charset=UTF-8' } });
}

async function sameSecret(a, b) {
  if (!a || !b) return false;
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(a)),
    crypto.subtle.digest('SHA-256', enc.encode(b))
  ]);
  const va = new Uint8Array(ha), vb = new Uint8Array(hb);
  let diff = va.length ^ vb.length;
  for (let i = 0; i < Math.max(va.length, vb.length); i++) diff |= (va[i] || 0) ^ (vb[i] || 0);
  return diff === 0;
}

function rateAllowed(ip) {
  const now = Date.now(), windowMs = 60_000, limit = 20;
  const old = recentRequests.get(ip) || [];
  const active = old.filter(t => now - t < windowMs);
  if (active.length >= limit) return false;
  active.push(now); recentRequests.set(ip, active);
  if (recentRequests.size > 1000) {
    for (const [key, values] of recentRequests) if (!values.some(t => now - t < windowMs)) recentRequests.delete(key);
  }
  return true;
}

function extractOutput(payload) {
  if (payload.output_text) return payload.output_text;
  for (const item of payload.output || []) {
    for (const content of item.content || []) {
      if (content.type === 'output_text' && content.text) return content.text;
    }
  }
  return '';
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const allowed = String(env.ALLOWED_ORIGIN || '').replace(/\/$/, '');
    const headers = cors(origin, allowed);

    if (!allowed || origin !== allowed) return json({ error: 'Deze website is niet toegestaan.' }, 403, headers);
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers });
    if (request.method !== 'POST') return json({ error: 'Alleen POST is toegestaan.' }, 405, headers);
    if (!env.OPENAI_API_KEY || !env.SCANNER_PIN) return json({ error: 'De servergeheimen zijn nog niet ingesteld.' }, 503, headers);

    const pin = request.headers.get('X-Scanner-Pin') || '';
    if (!(await sameSecret(pin, env.SCANNER_PIN))) return json({ error: 'Onjuiste scanner-PIN.' }, 401, headers);

    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    if (!rateAllowed(ip)) return json({ error: 'Te veel scans. Wacht één minuut.' }, 429, headers);

    let body;
    try { body = await request.json(); } catch { return json({ error: 'Ongeldige aanvraag.' }, 400, headers); }
    const image = String(body.image || '');
    if (!/^data:image\/(jpeg|png|webp);base64,/i.test(image) || image.length > MAX_IMAGE_CHARS) {
      return json({ error: 'Gebruik een JPG-, PNG- of WebP-foto van maximaal ongeveer 5 MB.' }, 400, headers);
    }

    const schema = {
      type: 'object', additionalProperties: false,
      properties: {
        cardName: { type: 'string' }, setName: { type: 'string' }, setCode: { type: 'string' },
        cardNumber: { type: 'string' }, variant: { type: 'string' }, language: { type: 'string' },
        confidence: { type: 'number', minimum: 0, maximum: 1 }
      },
      required: ['cardName','setName','setCode','cardNumber','variant','language','confidence']
    };

    const openai = await fetch('https://api.openai.com/v1/responses', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${env.OPENAI_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: env.OPENAI_MODEL || 'gpt-5.6-luna',
        store: false,
        max_output_tokens: 350,
        input: [{ role: 'user', content: [
          { type: 'input_text', text: 'Identify this Pokemon TCG card. Read the printed card name, collector number, set code/symbol if possible, language, and visible finish/variant. Variant must be one of: Normal, Holo, Reverse Holo, Cosmos Holo, Galaxy Holo, Cracked Ice Holo, Poke Ball, Great Ball, Master Ball, stamped, or Unknown. Never guess a set code when it is not visible or strongly identifiable. Return only the requested structured result.' },
          { type: 'input_image', image_url: image, detail: 'high' }
        ]}],
        text: { format: { type: 'json_schema', name: 'pokemon_card_identification', strict: true, schema } }
      })
    });

    const payload = await openai.json().catch(() => ({}));
    if (!openai.ok) {
      const message = payload?.error?.message || 'OpenAI kon de kaart niet analyseren.';
      return json({ error: message }, openai.status === 429 ? 429 : 502, headers);
    }

    let result;
    try { result = JSON.parse(extractOutput(payload)); }
    catch { return json({ error: 'De kaart werd niet betrouwbaar herkend. Maak een scherpere foto.' }, 422, headers); }
    return json(result, 200, headers);
  }
};
