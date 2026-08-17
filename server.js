const express = require('express');
const cors = require('cors');
const dns = require('dns').promises;

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

// Set this variable in Render under Environment Variables as your DQS Key
const DQS_KEY = process.env.SPAMHAUS_DQS_KEY;

app.get('/check-domain', async (req, res) => {
  const { domain } = req.query;

  if (!domain) {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }

  if (!DQS_KEY) {
    return res.status(500).json({ error: 'SPAMHAUS_DQS_KEY is not configured in Environment Variables.' });
  }

  try {
    // Spamhaus DQS Domain Blocklist (DBL) query format:
    // [domain].[DQS_KEY].dbl.dq.spamhaus.net
    const queryHost = `${domain}.${DQS_KEY}.dbl.dq.spamhaus.net`;

    const addresses = await dns.resolve4(queryHost);

    // If a DNS response is returned, the domain IS listed on Spamhaus DBL
    return res.json({
      domain: domain,
      listed: true,
      return_codes: addresses,
      status: 'Listed on Spamhaus Domain Blocklist (DBL)'
    });

  } catch (error) {
    // ENOTFOUND means DNS returned NXDOMAIN -> The domain is CLEAN
    if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
      return res.json({
        domain: domain,
        listed: false,
        status: 'Clean (Not listed on Spamhaus DBL)'
      });
    }

    return res.status(500).json({
      error: 'DNS Query Failed',
      details: error.message
    });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
