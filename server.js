const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

// Cache session token in memory to avoid requesting a new one every query
let cachedToken = null;
let tokenExpiry = 0;

async function getSpamhausToken() {
  const now = Date.now();
  if (cachedToken && now < tokenExpiry) {
    return cachedToken;
  }

  // Obtain live query token from Spamhaus checker session
  const res = await fetch('https://check.spamhaus.org/api/checker/v1/token', {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Referer': 'https://check.spamhaus.org/'
    }
  });

  if (!res.ok) {
    throw new Error(`Token Generation Failed [${res.status}]`);
  }

  const data = await res.json();
  cachedToken = data.token || data.access_token;
  // Expire local cache after 30 minutes
  tokenExpiry = now + 30 * 60 * 1000;

  return cachedToken;
}

app.get('/check-domain', async (req, res) => {
  const { domain } = req.query;

  if (!domain) {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }

  try {
    const token = await getSpamhausToken();

    // Direct fetch using the active session token
    const apiRes = await fetch(`https://check.spamhaus.org/api/checker/v1/domain/${encodeURIComponent(domain)}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
      }
    });

    const rawText = await apiRes.text();

    try {
      const data = JSON.parse(rawText);

      // Extract exact reputation score & sub-scores
      const mainScore = data.reputation_score ?? data.score ?? data.reputation?.score ?? 0;
      const sub = data.scores || data.reputation?.scores || { human: 0, identity: 0, infra: 0, malware: 0, smtp: 0 };

      return res.json({
        domain: domain,
        reputation_score: mainScore,
        scores: sub
      });
    } catch {
      return res.status(apiRes.status).send(rawText);
    }

  } catch (error) {
    return res.status(500).json({ error: 'Failed to query domain score', details: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
