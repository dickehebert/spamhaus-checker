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
    // 1. Get Access Token via Basic Auth on official API gateway
    const authHeader = Buffer.from(`${SPAMHAUS_USER}:${SPAMHAUS_PASS}`).toString('base64');
    
    const tokenRes = await fetch('https://api.spamhaus.org/v1/token', {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${authHeader}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: 'grant_type=client_credentials'
    });

    const tokenText = await tokenRes.text();

    if (!tokenRes.ok) {
      return res.status(tokenRes.status).json({
        error: 'Spamhaus Authentication Failed',
        details: tokenText
      });
    }

    const { access_token } = JSON.parse(tokenText);

    // 2. Query Official Spamhaus Intelligence API Endpoint
    const apiRes = await fetch(`https://api.spamhaus.org/v1/intel/domain/${encodeURIComponent(domain)}`, {
      headers: {
        'Authorization': `Bearer ${access_token}`,
        'Accept': 'application/json'
      }
    });

    const apiText = await apiRes.text();

    try {
      return res.json(JSON.parse(apiText));
    } catch {
      return res.status(apiRes.status).send(apiText);
    }

  } catch (error) {
    return res.status(500).json({ error: 'Server Error', details: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
