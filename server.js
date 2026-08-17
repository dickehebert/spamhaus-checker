const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const SPAMHAUS_USER = process.env.SPAMHAUS_USER || 'ybdfqtuk@81302263';
const SPAMHAUS_PASS = process.env.SPAMHAUS_PASS;

// 1. Authenticate & Obtain Bearer Token
async function getAuthToken() {
  const response = await fetch('https://api.spamhaus.org/api/v1/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'User-Agent': 'SpamhausProxyClient/1.0'
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
  return data.token || data.access_token;
}

// 2. Query Reputation Score Endpoint
app.get('/check-domain', async (req, res) => {
  const { domain } = req.query;

  if (!domain) {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }

  try {
    const token = await getAuthToken();

    // Query Spamhaus Intelligence API domain reputation endpoint
    const apiRes = await fetch(`https://api.spamhaus.org/api/intel/v1/byobject/domain/live/${encodeURIComponent(domain)}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
        'User-Agent': 'SpamhausProxyClient/1.0'
      }
    });

    const rawResult = await apiRes.text();

    try {
      const parsedData = JSON.parse(rawResult);
      return res.json(parsedData);
    } catch {
      return res.status(apiRes.status).send(rawResult);
    }

  } catch (error) {
    return res.status(500).json({ error: 'Spamhaus API Request Failed', details: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
