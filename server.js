const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

const SPAMHAUS_USER = process.env.SPAMHAUS_USER || 'kerlgtxr@81302263';
const SPAMHAUS_PASS = process.env.SPAMHAUS_PASS;

let cachedToken = null;
let tokenExpiry = 0;

// Fetch auth token from Spamhaus Intelligence API
async function getAuthToken() {
  const now = Date.now();
  if (cachedToken && now < tokenExpiry) {
    return cachedToken;
  }

  const response = await fetch('https://api.spamhaus.org/api/v1/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    },
    body: JSON.stringify({
      username: SPAMHAUS_USER,
      password: SPAMHAUS_PASS,
      realm: 'intel'
    })
  });

  const rawText = await response.text();

  if (!response.ok) {
    throw new Error(`Login Failed [${response.status}]: ${rawText}`);
  }

  const data = JSON.parse(rawText);
  cachedToken = data.token;
  tokenExpiry = data.expires ? (data.expires * 1000 - 60000) : (now + 12 * 3600 * 1000);
  
  return cachedToken;
}

app.get('/check-domain', async (req, res) => {
  const { domain } = req.query;

  if (!domain) {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }

  try {
    const token = await getAuthToken();

    // Query SIA Endpoint
    const apiRes = await fetch(`https://api.spamhaus.org/api/intel/v1/byobject/domain/live/${encodeURIComponent(domain)}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json'
      }
    });

    const rawResult = await apiRes.text();
    let parsedData;

    try {
      parsedData = JSON.parse(rawResult);
    } catch {
      // If Spamhaus returns non-JSON, wrap it safely
      return res.status(apiRes.status).json({
        error: `Spamhaus returned status ${apiRes.status}`,
        details: rawResult
      });
    }

    if (!apiRes.ok) {
      return res.status(apiRes.status).json({
        error: parsedData.message || 'API query failed',
        details: parsedData
      });
    }

    // Extract numerical scores
    const mainScore = parsedData.reputation_score ?? parsedData.score ?? 0;
    const subScores = parsedData.scores || { human: 0, identity: 0, infra: 0, malware: 0, smtp: 0 };

    return res.json({
      domain: domain,
      reputation_score: mainScore,
      scores: subScores
    });

  } catch (error) {
    return res.status(500).json({
      error: 'SIA Proxy Failed',
      details: error.message
    });
  }
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
