const { serialize } = require('cookie');
const { config, makePass, clientIp } = require('../lib');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ ok: false });
  const proof = req.body && req.body.proof ? req.body.proof : {};
  if (proof.webdriver || !proof.cookiesEnabled || !proof.ua) {
    return res.status(403).json({ ok: false });
  }
  const ip = clientIp(req);
  const ua = req.headers['user-agent'] || '';
  const token = makePass(ip, ua);
  res.setHeader('Set-Cookie', serialize(config.cookieName, token, { httpOnly: true, sameSite: 'lax', path: '/', maxAge: config.cookieTTLSeconds, secure: true }));
  res.status(200).json({ ok: true, redirect: typeof req.body.next === 'string' ? req.body.next : '/' });
};
