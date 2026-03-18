// SecureCheck v2 – Enhanced Security Scanner
// SSL Details + DNS Email Security (SPF, DMARC, DKIM) + alle bisherigen Checks

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
    return res.status(400).json({ error: 'Ungueltige URL' });
  }

  const domain = targetUrl.hostname;
  const checks = [];

  const [headersResult, sslResult, dnsResult, robotsResult] = await Promise.allSettled([
    pruefeHeaders(url, targetUrl),
    pruefeSsl(domain),
    pruefeDns(domain),
    pruefeRobots(targetUrl)
  ]);

  if (headersResult.status === 'fulfilled') checks.push(...headersResult.value);
  if (sslResult.status === 'fulfilled') checks.push(...sslResult.value);
  if (dnsResult.status === 'fulfilled') checks.push(...dnsResult.value);
  if (robotsResult.status === 'fulfilled') checks.push(...robotsResult.value);

  return res.status(200).json({ checks, domain });
}

async function pruefeHeaders(url, targetUrl) {
  const checks = [];
  const isHttps = targetUrl.protocol === 'https:';

  checks.push({
    name: 'HTTPS',
    status: isHttps ? 'pass' : 'fail',
    description: isHttps
      ? 'Die Website verwendet HTTPS - Verbindung ist verschluesselt.'
      : 'Die Website verwendet kein HTTPS! Daten werden unverschluesselt uebertragen.',
    detail: 'Protokoll: ' + targetUrl.protocol
  });

  let headers = {};
  try {
    const response = await fetch(url, {
      method: 'HEAD',
      redirect: 'manual',
      headers: { 'User-Agent': 'SecureCheck-Scanner/2.0' }
    });
    headers = Object.fromEntries(response.headers.entries());
    checks.push({ name: 'HTTP to HTTPS Redirect', status: 'pass', description: 'Website verwendet bereits HTTPS direkt.' });
  } catch(e) {
    checks.push({ name: 'Erreichbarkeit', status: 'fail', description: 'Website nicht erreichbar: ' + e.message });
    return checks;
  }

  const headerChecks = [
    { key: 'strict-transport-security', name: 'HSTS Header', pass: 'HSTS aktiv - Browser erzwingen HTTPS.', fail: 'Kein HSTS Header.' },
    { key: 'x-frame-options', name: 'X-Frame-Options', pass: 'Schutz gegen Clickjacking aktiv.', fail: 'Kein X-Frame-Options - Clickjacking Risiko.', severity: 'warn' },
    { key: 'content-security-policy', name: 'Content Security Policy', pass: 'CSP aktiv - XSS Schutz.', fail: 'Kein CSP Header - XSS Risiko.', severity: 'warn' },
    { key: 'x-content-type-options', name: 'X-Content-Type-Options', pass: 'nosniff gesetzt.', fail: 'X-Content-Type-Options fehlt.', severity: 'warn' },
    { key: 'referrer-policy', name: 'Referrer Policy', pass: 'Referrer Policy gesetzt.', fail: 'Keine Referrer Policy.', severity: 'warn' },
    { key: 'permissions-policy', name: 'Permissions Policy', pass: 'Permissions Policy aktiv.', fail: 'Keine Permissions Policy.', severity: 'warn' }
  ];

  for (const h of headerChecks) {
    const value = headers[h.key];
    checks.push({
      name: h.name,
      status: value ? 'pass' : (h.severity || 'fail'),
      description: value ? h.pass : h.fail,
      detail: value ? value.substring(0, 100) : 'Nicht gesetzt'
    });
  }

  const server = headers['server'];
  checks.push({
    name: 'Server Information',
    status: !server || server.length < 20 ? 'pass' : 'warn',
    description: !server || server.length < 20 ? 'Server gibt keine detaillierten Versionsinformationen preis.' : 'Server Header enthaelt Versionsinformationen.',
    detail: server || 'Nicht gesetzt'
  });

  const poweredBy = headers['x-powered-by'];
  checks.push({
    name: 'X-Powered-By',
    status: !poweredBy ? 'pass' : 'warn',
    description: !poweredBy ? 'X-Powered-By nicht gesetzt - gut!' : 'X-Powered-By gibt Technologie-Stack preis.',
    detail: poweredBy || 'Nicht gesetzt'
  });

  return checks;
}

async function pruefeSsl(domain) {
  const checks = [];
  try {
    const res = await fetch('https://api.ssllabs.com/api/v3/analyze?host=' + domain + '&startNew=off&fromCache=on&maxAge=24', {
      headers: { 'User-Agent': 'SecureCheck/2.0' }
    });
    const data = await res.json();

    if (data.status === 'READY' && data.endpoints?.length > 0) {
      const grade = data.endpoints[0].grade;
      checks.push({
        name: 'SSL/TLS Grade (SSL Labs)',
        status: ['A+', 'A'].includes(grade) ? 'pass' : ['A-', 'B'].includes(grade) ? 'warn' : 'fail',
        description: 'SSL Labs Bewertung: ' + grade + '. ' + (grade === 'A+' ? 'Ausgezeichnet!' : grade === 'A' ? 'Gut.' : 'Verbesserung empfohlen.'),
        detail: 'Grade: ' + grade
      });
    } else {
      checks.push({
        name: 'SSL/TLS Grade (SSL Labs)',
        status: 'warn',
        description: 'SSL Analyse laeuft noch - bitte in 1-2 Minuten erneut scannen.',
        detail: 'Status: ' + (data.status || 'Wird analysiert')
      });
    }
  } catch {
    checks.push({ name: 'SSL/TLS Grade', status: 'warn', description: 'SSL Labs Analyse nicht verfuegbar.', detail: 'Fallback' });
  }
  return checks;
}

async function pruefeDns(domain) {
  const checks = [];
  const api = 'https://dns.google/resolve?name=';

  try {
    const res = await fetch(api + domain + '&type=TXT');
    const data = await res.json();
    const spf = data.Answer?.map(r => r.data).find(r => r.includes('v=spf1'));
    checks.push({
      name: 'SPF Record (Email Security)',
      status: spf ? 'pass' : 'warn',
      description: spf ? 'SPF Record vorhanden - Schutz gegen Email-Spoofing.' : 'Kein SPF Record - Emails koennten gefaelscht werden.',
      detail: spf || 'Nicht gesetzt'
    });
  } catch {}

  try {
    const res = await fetch(api + '_dmarc.' + domain + '&type=TXT');
    const data = await res.json();
    const dmarc = data.Answer?.find(r => r.data?.includes('v=DMARC1'))?.data;
    checks.push({
      name: 'DMARC Record (Email Security)',
      status: dmarc ? 'pass' : 'warn',
      description: dmarc ? 'DMARC Record vorhanden - Email Authentifizierung aktiv.' : 'Kein DMARC Record.',
      detail: dmarc || 'Nicht gesetzt'
    });
  } catch {}

  try {
    const res = await fetch(api + domain + '&type=MX');
    const data = await res.json();
    const hasMx = data.Answer?.length > 0;
    checks.push({
      name: 'MX Records (Email)',
      status: hasMx ? 'pass' : 'warn',
      description: hasMx ? 'MX Records vorhanden - Domain kann Emails empfangen.' : 'Keine MX Records.',
      detail: data.Answer?.map(r => r.data).join(', ') || 'Keine MX Records'
    });
  } catch {}

  try {
    const res = await fetch(api + domain + '&type=CAA');
    const data = await res.json();
    const caa = data.Answer?.length > 0;
    checks.push({
      name: 'CAA Record (SSL Schutz)',
      status: caa ? 'pass' : 'warn',
      description: caa ? 'CAA Record vorhanden - nur autorisierte CAs duerfen Zertifikate ausstellen.' : 'Kein CAA Record.',
      detail: data.Answer?.map(r => r.data).join(', ') || 'Nicht gesetzt'
    });
  } catch {}

  return checks;
}

async function pruefeRobots(targetUrl) {
  const checks = [];
  try {
    const res = await fetch(targetUrl.protocol + '//' + targetUrl.hostname + '/robots.txt');
    if (res.status === 200) {
      const text = await res.text();
      const sensitive = ['/admin', '/wp-admin', '/backend', '/api', '/config', '/backup'].filter(p => text.toLowerCase().includes(p));
      checks.push({
        name: 'Robots.txt',
        status: sensitive.length > 0 ? 'warn' : 'pass',
        description: sensitive.length > 0
          ? 'Robots.txt enthaelt sensitive Pfade: ' + sensitive.join(', ')
          : 'Robots.txt vorhanden, keine sensiblen Pfade gefunden.',
        detail: text.split('\n').length + ' Zeilen'
      });
    }
  } catch {}
  return checks;
}
