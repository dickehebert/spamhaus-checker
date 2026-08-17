const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

// 1. Manual Token Generation Endpoint
app.post('/generate-token', async (req, res) => {
  const { username, password, realm } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and Password are required' });
  }

  try {
    const response = await fetch('https://api.spamhaus.org/api/v1/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        username: username.trim(),
        password: password.trim(),
        realm: realm || 'intel'
      })
    });

    const rawText = await response.text();

    if (!response.ok) {
      return res.status(response.status).json({ 
        error: `Login Failed [HTTP ${response.status}]`, 
        details: rawText 
      });
    }

    const data = JSON.parse(rawText);
    return res.json({
      success: true,
      token: data.token,
      expires: data.expires || null
    });

  } catch (error) {
    return res.status(500).json({ error: 'Authentication Request Failed', details: error.message });
  }
});

// 2. Domain Score Lookup Endpoint using Bearer Token
app.post('/check-domains', async (req, res) => {
  const { token, domains } = req.body;

  if (!token) {
    return res.status(401).json({ error: 'Valid Bearer Token required' });
  }

  if (!domains || !Array.isArray(domains) || domains.length === 0) {
    return res.status(400).json({ error: 'Domains array is required' });
  }

  const results = [];

  for (const domain of domains) {
    const cleanDomain = domain.trim();
    if (!cleanDomain) continue;

    try {
      // Query official SIA endpoint
      const apiRes = await fetch(`https://api.spamhaus.org/api/intel/v1/byobject/domain/live/${encodeURIComponent(cleanDomain)}`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/json'
        }
      });

      const rawText = await apiRes.text();

      if (apiRes.status === 404) {
        // Domain clean or not tracked in SIA dataset
        results.push({
          domain: cleanDomain,
          reputation_score: 0,
          scores: { human: 0, identity: 0, infra: 0, malware: 0, smtp: 0 },
          status: 'Clean / Unlisted'
        });
        continue;
      }

      if (!apiRes.ok) {
        results.push({
          domain: cleanDomain,
          error: `HTTP ${apiRes.status}`,
          details: rawText
        });
        continue;
      }

      const parsed = JSON.parse(rawText);
      results.push({
        domain: cleanDomain,
        reputation_score: parsed.reputation_score ?? parsed.score ?? 0,
        scores: parsed.scores || { human: 0, identity: 0, infra: 0, malware: 0, smtp: 0 }
      });

    } catch (err) {
      results.push({ domain: cleanDomain, error: err.message });
    }
  }

  return res.json({ success: true, results });
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
