const express = require('express');
const cors = require('cors');
const dns = require('dns').promises;

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const DQS_KEY = process.env.SPAMHAUS_DQS_KEY;

app.get('/check-domain', async (req, res) => {
  const { domain } = req.query;

  if (!domain) {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }

  if (!DQS_KEY) {
    return res.status(500).json({ error: 'SPAMHAUS_DQS_KEY is missing in Render Environment Variables.' });
  }

  try {
    // Query Spamhaus DBL via native DNS
    const queryHost = `${domain}.${DQS_KEY}.dbl.dq.spamhaus.net`;
    const addresses = await dns.resolve4(queryHost);

    // Map DNS return codes to category scores
    const sub = { human: 0, identity: 0, infra: 0, malware: 0, smtp: 0 };
    let totalScore = 0;

    addresses.forEach(ip => {
      if (ip === '127.0.1.2') { sub.smtp = 10; totalScore += 10; }
      if (ip === '127.0.1.4') { sub.identity = 10; totalScore += 10; }
      if (ip === '127.0.1.5') { sub.malware = 10; totalScore += 10; }
      if (ip === '127.0.1.6') { sub.infra = 10; totalScore += 10; }
      if (ip === '127.0.1.102') { sub.human = 5; totalScore += 5; }
    });

    return res.json({
      domain: domain,
      reputation_score: totalScore,
      scores: sub
    });

  } catch (error) {
    // ENOTFOUND / ENODATA means the domain is clean (0 score)
    if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
      return res.json({
        domain: domain,
        reputation_score: 0,
        scores: { human: 0, identity: 0, infra: 0, malware: 0, smtp: 0 }
      });
    }

    return res.status(500).json({ error: 'DNS Query Failed', details: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
