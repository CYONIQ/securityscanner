// SecureCheck – Security Scanner Backend
// Prüft SSL, Security Headers, HTTPS Redirect und mehr

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL erforderlich' });

  let targetUrl;
  try {
    targetUrl = new URL(url);
  } catch {
    return res.status(400).json({ error: 'Ungültige URL' });
  }

  const checks = [];

  // 1. HTTPS Check
  const isHttps = targetUrl.protocol === 'https:';
  checks.push({
    name: 'HTTPS',
    status: isHttps ? 'pass' : 'fail',
    description: isHttps
      ? 'Die Website verwendet HTTPS – Verbindung ist verschlüsselt.'
      : 'Die Website verwendet kein HTTPS! Alle Daten werden unverschlüsselt übertragen.',
    detail: `Protokoll: ${targetUrl.protocol}`
  });

  // 2. Headers abrufen
  let headers = {};
  let responseStatus = 0;
  let httpRedirectsToHttps = false;

  try {
    const response = await fetch(url, {
      method: 'HEAD',
      redirect: 'manual',
      headers: { 'User-Agent': 'SecureCheck-Scanner/1.0' }
    });
    headers = Object.fromEntries(response.headers.entries());
    responseStatus = response.status;

    // HTTP → HTTPS Redirect prüfen
    if (!isHttps) {
      const httpUrl = url.replace('https://', 'http://');
      try {
        const httpRes = await fetch(httpUrl, { method: 'HEAD', redirect: 'manual' });
        const location = httpRes.headers.get('location');
        httpRedirectsToHttps = location && location.startsWith('https://');
      } catch {}
    }
  } catch(e) {
    checks.push({
      name: 'Erreichbarkeit',
      status: 'fail',
      description: `Website nicht erreichbar: ${e.message}`,
    });
    return res.status(200).json({ checks });
  }

  // 3. HTTPS Redirect
  if (!isHttps) {
    checks.push({
      name: 'HTTP → HTTPS Redirect',
      status: httpRedirectsToHttps ? 'pass' : 'warn',
      description: httpRedirectsToHttps
        ? 'HTTP wird automatisch auf HTTPS weitergeleitet.'
        : 'Kein automatischer Redirect von HTTP zu HTTPS gefunden.',
    });
  } else {
    checks.push({
      name: 'HTTP → HTTPS Redirect',
      status: 'pass',
      description: 'Website verwendet bereits HTTPS direkt.',
    });
  }

  // 4. HSTS Header
  const hsts = headers['strict-transport-security'];
  checks.push({
    name: 'HSTS Header',
    status: hsts ? 'pass' : 'fail',
    description: hsts
      ? 'HSTS ist aktiv – Browser erzwingen HTTPS Verbindungen.'
      : 'Kein HSTS Header! Browser könnten unsichere HTTP Verbindungen zulassen.',
    detail: hsts || 'Nicht gesetzt'
  });

  // 5. X-Frame-Options
  const xframe = headers['x-frame-options'];
  checks.push({
    name: 'X-Frame-Options',
    status: xframe ? 'pass' : 'warn',
    description: xframe
      ? 'X-Frame-Options gesetzt – Schutz gegen Clickjacking.'
      : 'Kein X-Frame-Options Header – mögliches Clickjacking Risiko.',
    detail: xframe || 'Nicht gesetzt'
  });

  // 6. Content Security Policy
  const csp = headers['content-security-policy'];
  checks.push({
    name: 'Content Security Policy',
    status: csp ? 'pass' : 'warn',
    description: csp
      ? 'CSP Header vorhanden – Schutz gegen XSS Angriffe.'
      : 'Kein CSP Header – erhöhtes XSS Risiko.',
    detail: csp ? csp.substring(0, 80) + '...' : 'Nicht gesetzt'
  });

  // 7. X-Content-Type-Options
  const xcto = headers['x-content-type-options'];
  checks.push({
    name: 'X-Content-Type-Options',
    status: xcto === 'nosniff' ? 'pass' : 'warn',
    description: xcto === 'nosniff'
      ? 'nosniff gesetzt – Browser dürfen MIME-Type nicht erraten.'
      : 'X-Content-Type-Options fehlt oder falsch gesetzt.',
    detail: xcto || 'Nicht gesetzt'
  });

  // 8. Referrer Policy
  const referrer = headers['referrer-policy'];
  checks.push({
    name: 'Referrer Policy',
    status: referrer ? 'pass' : 'warn',
    description: referrer
      ? 'Referrer Policy gesetzt – kontrolliert welche Daten weitergegeben werden.'
      : 'Keine Referrer Policy – URLs könnten an externe Seiten weitergegeben werden.',
    detail: referrer || 'Nicht gesetzt'
  });

  // 9. Server Header (Information Disclosure)
  const server = headers['server'];
  const serverSafe = !server || server.length < 20;
  checks.push({
    name: 'Server Information',
    status: serverSafe ? 'pass' : 'warn',
    description: serverSafe
      ? 'Server gibt keine detaillierten Versionsinformationen preis.'
      : 'Server Header enthält detaillierte Versionsinformationen – könnte Angriffe erleichtern.',
    detail: server || 'Nicht gesetzt'
  });

  // 10. X-Powered-By (Information Disclosure)
  const poweredBy = headers['x-powered-by'];
  checks.push({
    name: 'X-Powered-By',
    status: !poweredBy ? 'pass' : 'warn',
    description: !poweredBy
      ? 'X-Powered-By Header nicht gesetzt – gut!'
      : 'X-Powered-By Header gibt Technologie-Stack preis.',
    detail: poweredBy || 'Nicht gesetzt'
  });

  // 11. Permissions Policy
  const permissions = headers['permissions-policy'];
  checks.push({
    name: 'Permissions Policy',
    status: permissions ? 'pass' : 'warn',
    description: permissions
      ? 'Permissions Policy gesetzt – Browser-Features werden kontrolliert.'
      : 'Keine Permissions Policy – Kamera, Mikrofon etc. könnten uneingeschränkt zugänglich sein.',
    detail: permissions || 'Nicht gesetzt'
  });

  return res.status(200).json({ checks });
}
