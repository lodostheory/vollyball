// VOLLYBALL MANIA 팀 저장 서버 (Cloudflare Workers + KV)
//   GET  /teams          팀 목록
//   GET  /teams/:name    팀의 저장된 위치
//   PUT  /teams/:name    { password, data } — 없으면 새로 만들고, 있으면 비밀번호 확인 후 덮어씀
//   DELETE /teams/:name         { password } — 팀 삭제
//   POST   /teams/:name/rename  { password, newName } — 팀 이름 변경
const IDS = ['base', 'left', 'right', 'quick', 'a', 'b', 'ba', 'time'];
const MAX_TEAMS = 300;
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,PUT,POST,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Max-Age': '86400',
};
const json = (body, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...CORS },
});
const fail = (status, error) => json({ error }, status);

function cleanName(raw) {
  const name = String(raw || '').normalize('NFC').trim().replace(/\s+/g, ' ');
  if (!name || [...name].length > 20 || /[\u0000-\u001f\u007f\/\\]/.test(name)) return null;
  return name;
}
const isPoint = p => Array.isArray(p) && p.length === 2 && p.every(v => typeof v === 'number' && isFinite(v) && Math.abs(v) <= 200);
function cleanData(d) {
  if (!d || typeof d !== 'object') return null;
  const out = {};
  for (const id of IDS) {
    const v = d[id];
    if (!v || !Array.isArray(v.pos) || v.pos.length !== 9 || !v.pos.every(isPoint)) return null;
    out[id] = { pos: v.pos };
    for (const f of ['set', 'atk', 'target', 'decoy']) {
      if (v[f] === undefined) continue;
      if (!isPoint(v[f])) return null;
      out[id][f] = v[f];
    }
  }
  return out;
}
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
async function hashPassword(password, saltHex) {
  const salt = new Uint8Array(saltHex.match(/../g).map(h => parseInt(h, 16)));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100000 }, key, 256));
}

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    const parts = new URL(req.url).pathname.split('/').filter(Boolean);
    const renaming = parts.length === 3 && parts[2] === 'rename';
    if (parts[0] !== 'teams' || (parts.length > 2 && !renaming)) return fail(404, 'not_found');

    if (parts.length === 1) {
      if (req.method !== 'GET') return fail(405, 'method_not_allowed');
      const teams = [];
      let cursor;
      do {
        const page = await env.TEAMS.list({ prefix: 'team:', cursor });
        for (const k of page.keys) teams.push({ name: k.metadata?.name || k.name.slice(5), updatedAt: k.metadata?.updatedAt || null });
        cursor = page.list_complete ? null : page.cursor;
      } while (cursor);
      teams.sort((a, b) => a.name.localeCompare(b.name, 'ko'));
      return json({ teams });
    }

    let name;
    try { name = cleanName(decodeURIComponent(parts[1])); } catch (e) { name = null; }
    if (!name) return fail(400, 'bad_name');
    const key = 'team:' + name;
    const stored = await env.TEAMS.get(key, 'json');

    if (renaming ? req.method !== 'POST' : !['GET', 'PUT', 'DELETE'].includes(req.method)) return fail(405, 'method_not_allowed');
    if (req.method === 'GET') {
      if (!stored) return fail(404, 'no_team');
      return json({ name: stored.name, data: stored.data, updatedAt: stored.updatedAt });
    }

    const text = await req.text();
    if (text.length > 20000) return fail(413, 'too_large');
    let body;
    try { body = JSON.parse(text); } catch (e) { return fail(400, 'bad_json'); }
    const password = typeof body.password === 'string' ? body.password : '';
    if (password.length < 4 || password.length > 64) return fail(400, 'bad_password');
    if (req.method !== 'PUT') {          // 삭제·이름 변경
      if (!stored) return fail(404, 'no_team');
      if (await hashPassword(password, stored.salt) !== stored.hash) return fail(401, 'wrong_password');
      if (req.method === 'DELETE') { await env.TEAMS.delete(key); return json({ deleted: name }); }
      const newName = cleanName(body.newName);
      if (!newName) return fail(400, 'bad_name');
      if (newName === name) return json({ name });
      if (await env.TEAMS.get('team:' + newName)) return fail(409, 'team_exists');
      const updatedAt = new Date().toISOString();
      await env.TEAMS.put('team:' + newName, JSON.stringify({ ...stored, name: newName, updatedAt }), { metadata: { name: newName, updatedAt } });
      await env.TEAMS.delete(key);
      return json({ name: newName, updatedAt });
    }
    const data = cleanData(body.data);
    if (!data) return fail(400, 'bad_data');

    let salt, hash;
    if (stored) {
      if (await hashPassword(password, stored.salt) !== stored.hash) return fail(401, 'wrong_password');
      ({ salt, hash } = stored);
    } else {
      if (body.create !== true) return fail(404, 'no_team');
      const list = await env.TEAMS.list({ prefix: 'team:', limit: 1000 });
      if (list.keys.length >= MAX_TEAMS) return fail(403, 'too_many_teams');
      salt = hex(crypto.getRandomValues(new Uint8Array(16)));
      hash = await hashPassword(password, salt);
    }
    if (stored && body.create === true) return fail(409, 'team_exists');
    const updatedAt = new Date().toISOString();
    await env.TEAMS.put(key, JSON.stringify({ name, salt, hash, data, updatedAt }), { metadata: { name, updatedAt } });
    return json({ name, updatedAt }, stored ? 200 : 201);
  },
};
