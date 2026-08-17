const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const SPAMHAUS_USER = process.env.SPAMHAUS_USER;
const SPAMHAUS_PASS = process.env.SPAMHAUS_PASS;

async function getAuthToken() {
  const credentials = Buffer.from(`${SPAMHAUS_USER}:${SPAMHAUS_PASS}`).toString('base64');

  const response = await fetch('https://api.spamhaus.org/v1/token', {
    method: 'POST',
    headers: {
      'Authorization': `Basic ${credentials}`,
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': 'Mozilla/5.0'
    },
    body: 'grant_type=client_credentials'
  });

  const data = await response.json();
  return data.access_token;
}

app.get('/check-domain', async (req, res) => {
  const { domain } = req.query;

  if (!domain) {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }

  try {
    const token = await getAuthToken();

    const apiRes = await fetch(`https://check.spamhaus.org/api/checker/v1/domain/${encodeURIComponent(domain)}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0'
      }
    });

    const result = await apiRes.json();
    return res.json(result);
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch domain data', details: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
