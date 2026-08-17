const express = require('express');
const cors = require('cors');
const puppeteer = require('puppeteer');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

app.get('/check-domain', async (req, res) => {
  const { domain } = req.query;

  if (!domain) {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }

  let browser;
  try {
    // Launch headless Chromium instance
    browser = await puppeteer.launch({
      headless: "new",
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--single-process'
      ]
    });

    const page = await browser.newPage();

    // Set real browser User-Agent
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

    // Navigate to live Spamhaus web checker
    const targetUrl = `https://www.spamhaus.org/domain-reputation?domain=${encodeURIComponent(domain)}`;
    await page.goto(targetUrl, { waitUntil: 'networkidle2', timeout: 30000 });

    // Wait for the dynamic score card container to populate
    await page.waitForSelector('.big-score, [class*="score"], h1, div', { timeout: 15000 });

    // Extract exact dynamic scores directly from the page DOM
    const resultData = await page.evaluate(() => {
      const bodyText = document.body.innerText;
      
      // Match reputation score text
      const scoreMatch = bodyText.match(/Reputation score\s*([\d\.]+)/i) || bodyText.match(/(\d+\.?\d*)\s*Reputation/i);
      const mainScore = scoreMatch ? parseFloat(scoreMatch[1]) : 0;

      // Extract category scores
      const extractCategory = (name) => {
        const reg = new RegExp(`${name}\\s*([\\d\\.]+)`, 'i');
        const m = bodyText.match(reg);
        return m ? parseFloat(m[1]) : 0;
      };

      return {
        reputation_score: mainScore,
        scores: {
          human: extractCategory('human'),
          identity: extractCategory('identity'),
          infra: extractCategory('infra'),
          malware: extractCategory('malware'),
          smtp: extractCategory('smtp')
        }
      };
    });

    await browser.close();
    return res.json({ domain, ...resultData });

  } catch (error) {
    if (browser) await browser.close();
    return res.status(500).json({ error: 'Failed to scrape live score', details: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
