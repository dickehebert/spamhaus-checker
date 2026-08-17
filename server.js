const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

// 1. Generate Token Route
app.post('/generate-token', async (req, res) => {
  const { username, password, realm } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and Password required' });
  }

  try {
    const response = await fetch('https://api.spamhaus.org/api/v1/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({
        username: username.trim(),
        password: password.trim(),
        realm: realm || 'intel'
      })
    });

    const rawText = await response.text();

    if (!response.ok) {
      return res.status(response.status).json({ error: `Login Failed [${response.status}]`, details: rawText });
    }

    const data = JSON.parse(rawText);
    return res.json({ success: true, token: data.token });

  } catch (error) {
    return res.status(500).json({ error: 'Auth failed', details: error.message });
  }
});

// 2. Query Domain Score using v2 SIA Endpoints
app.post('/check-domains', async (req, res) => {
  const { token, domains } = req.body;

  if (!token) return res.status(401).json({ error: 'Token missing' });
  if (!domains || !Array.isArray(domains)) return res.status(400).json({ error: 'Domains array required' });

  const results = [];

  for (const domain of domains) {
    const cleanDomain = domain.trim().toLowerCase();
    if (!cleanDomain) continue;

    try {
      // Execute v2 General Domain and Dimensions requests in parallel
      const headers = { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' };

      const [genRes, dimRes] = await Promise.all([
        fetch(`https://api.spamhaus.org/api/intel/v2/byobject/domain/${encodeURIComponent(cleanDomain)}`, { headers }),
        fetch(`https://api.spamhaus.org/api/intel/v2/byobject/domain/${encodeURIComponent(cleanDomain)}/dimensions`, { headers })
      ]);

      const genData = genRes.ok ? await genRes.json() : {};
      const dimData = dimRes.ok ? await dimRes.json() : {};

      // Parse overall score (v2 returns "score")
      const mainScore = genData.score ?? 0;

      // Parse sub-dimension scores
      const dimensions = {
        human: dimData.human ?? 0,
        identity: dimData.identity ?? 0,
        infra: dimData.infra ?? 0,
        malware: dimData.malware ?? 0,
        smtp: dimData.smtp ?? 0
      };

      // Extract WHOIS info if provided by v2 API
      const whois = genData.whois || {};

      results.push({
        domain: cleanDomain,
        reputation_score: mainScore,
        scores: dimensions,
        whois: {
          created: whois.created ? new Date(whois.created * 1000).toLocaleDateString() : null,
          expires: whois.expires ? new Date(whois.expires * 1000).toLocaleDateString() : null,
          registrar: whois.registrar || null
        }
      });

    } catch (err) {
      results.push({ domain: cleanDomain, error: err.message });
    }
  }

  return res.json({ success: true, results });
});

app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
