const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const SPAMHAUS_USER = process.env.SPAMHAUS_USER;
const SPAMHAUS_PASS = process.env.SPAMHAUS_PASS;

// Official Spamhaus Intelligence API login function
async function getAuthToken() {
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
    throw new Error(`Token Login Failed [${response.status}]: ${rawText}`);
  }

  const data = JSON.parse(rawText);
  return data.token; // Returns the SIA Bearer token
}

app.get('/check-domain', async (req, res) => {
  const { domain } = req.query;

  if (!domain) {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }

  try {
    const token = await getAuthToken();
    
    // Official Spamhaus Intelligence Domain Lookup Endpoint
    const apiRes = await fetch(`https://api.spamhaus.org/api/intel/v1/byobject/domain/live/${encodeURIComponent(domain)}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json'
      }
    });

    const resultText = await apiRes.text();
    
    try {
      const jsonResult = JSON.parse(resultText);
      return res.json(jsonResult);
    } catch {
      return res.status(apiRes.status).send(resultText);
    }

  } catch (error) {
    return res.status(500).json({ error: 'Spamhaus API Error', details: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
