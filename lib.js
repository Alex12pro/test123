const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const config = JSON.parse(fs.readFileSync(path.join(__dirname, 'astral.config.json'), 'utf8'));
const secret = process.env.ASTRAL_SECRET || 'change-this-in-production-to-a-long-random-secret';
function sha(v){return crypto.createHash('sha256').update(String(v)).digest('hex')}
function hmac(v){return crypto.createHmac('sha256', secret).update(v).digest('hex')}
function makePass(ip, ua){const body=Buffer.from(JSON.stringify({ip:sha(ip).slice(0,24),ua:sha(ua||'').slice(0,24),exp:Date.now()+config.cookieTTLSeconds*1000})).toString('base64url');return `${body}.${hmac(body)}`}
function verifyPass(token, ip, ua){if(!token||!token.includes('.')) return false; const [body,sig]=token.split('.'); if(hmac(body)!==sig) return false; try{const data=JSON.parse(Buffer.from(body,'base64url').toString('utf8')); return data.exp >= Date.now() && data.ip===sha(ip).slice(0,24) && data.ua===sha(ua||'').slice(0,24)}catch{return false}}
function clientIp(req){return (req.headers['x-forwarded-for']||'').split(',')[0].trim() || req.socket?.remoteAddress || 'unknown'}
function suspiciousUA(ua){if(!ua) return true; return /(python|curl|wget|scrapy|axios|node-fetch|go-http-client|postmanruntime|httpclient|phantom|selenium|playwright)/i.test(ua)}
module.exports = { config, makePass, verifyPass, clientIp, suspiciousUA };
