const { NextResponse } = require('next/server');
const fs = require('fs');
const path = require('path');
const { config, verifyPass, suspiciousUA } = require('./lib');

function isExcluded(pathname) {
  return pathname === config.challengePath || pathname.startsWith(config.assetsPath + '/') || pathname === config.sdkPath || pathname.startsWith('/api/') || pathname.includes('.');
}

module.exports = function middleware(req) {
  const pathname = req.nextUrl.pathname;
  if (isExcluded(pathname)) return NextResponse.next();

  const ip = req.headers.get('x-forwarded-for')?.split(',')[0].trim() || 'unknown';
  const ua = req.headers.get('user-agent') || '';
  const token = req.cookies.get(config.cookieName)?.value;

  if (suspiciousUA(ua)) {
    return new NextResponse('Blocked by Astral', { status: 403 });
  }

  if (!verifyPass(token, ip, ua)) {
    const url = req.nextUrl.clone();
    url.pathname = config.challengePath;
    url.searchParams.set('next', pathname + (req.nextUrl.search || ''));
    return NextResponse.redirect(url);
  }

  return NextResponse.next();
}

module.exports.config = {
  matcher: ['/((?!_next|favicon.ico).*)']
};
