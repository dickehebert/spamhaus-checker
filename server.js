const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const SPAMHAUS_USER = process.env.SPAMHAUS_USER;
const SPAMHAUS_PASS = process.env.SPAMHAUS_PASS;

app.get('/check-domain', async (req, res) => {
  const { domain } = req.query;

  if (!domain) {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }

  try {
    // 1. First Attempt: Query check.spamhaus.org using Basic Auth
    const basicAuth = Buffer.from(`${SPAMHAUS_USER}:${SPAMHAUS_PASS}`).toString('base64');
    
    let apiRes = await fetch(`https://check.spamhaus.org/api/checker/v1/domain/${encodeURIComponent(domain)}`, {
      headers: {
        'Authorization': `Basic ${basicAuth}`,
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
      }
    });

    let rawText = await apiRes.text();

    // 2. Second Attempt: If Basic Auth is rejected, try Token Auth via submit.spamhaus.org
    if (apiRes.status === 401 || apiRes.status === 404) {
      const authRes = await fetch('https://submit.spamhaus.org/api/v1/authenticate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: SPAMHAUS_USER, password: SPAMHAUS_PASS })
      });

      const authText = await authRes.text();

      if (!authRes.ok) {
        return res.status(authRes.status).json({
          error: "Spamhaus Authentication Failed",
          details: authText
        });
      }

      const authData = JSON.parse(authText);
      const token = authData.token || authData.access_token;

      // Query checker with the generated Bearer Token
      apiRes = await fetch(`https://check.spamhaus.org/api/checker/v1/domain/${encodeURIComponent(domain)}`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/json',
          'User-Agent': 'Mozilla/5.0'
        }
      });

      rawText = await apiRes.text();
    }

    // Return response JSON or raw output
    try {
      const jsonResult = JSON.parse(rawText);
      return res.json(jsonResult);
    } catch {
      return res.status(apiRes.status).send(rawText);
    }

  } catch (error) {
    return res.status(500).json({ error: 'Proxy Request Failed', details: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
