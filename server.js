const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

app.get('/check-domain', async (req, res) => {
  const { domain } = req.query;

  if (!domain) {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }

  try {
    // Direct call to the main www.spamhaus.org reputation endpoint
    const response = await fetch(`https://www.spamhaus.org/api/v1/reputation/domain/${encodeURIComponent(domain)}`, {
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Referer': 'https://www.spamhaus.org/domain-reputation'
      }
    });

    const rawText = await response.text();

    try {
      const data = JSON.parse(rawText);

      // Return the exact score values
      return res.json({
        domain: domain,
        reputation_score: data.reputation_score ?? data.score ?? 0,
        scores: {
          human: data.scores?.human ?? 0,
          identity: data.scores?.identity ?? 0,
          infra: data.scores?.infra ?? 0,
          malware: data.scores?.malware ?? 0,
          smtp: data.scores?.smtp ?? 0
        }
      });
    } catch {
      // If Spamhaus changes structural format, output raw JSON response
      return res.status(response.status).send(rawText);
    }

  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch score', details: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
