# Landing Pages

Static landing pages for Civvra brands.

| Domain | Page | Hosting |
|---|---|---|
| civvra.com | `civvra/index.html` | Cloudflare Pages or GitHub Pages |
| regohub.com | `regohub/index.html` | Cloudflare Pages or GitHub Pages |

## Deploy to Cloudflare Pages

1. Go to **Cloudflare Dashboard → Workers & Pages → Create → Pages**
2. Connect your GitHub repo
3. Build settings: Framework = **None**, Build output = `website`
4. Set routes:
   - `civvra.com/*` → `website/civvra/index.html`
   - `regohub.com/*` → `website/regohub/index.html`

## Deploy to GitHub Pages

1. Go to repo **Settings → Pages**
2. Source: **GitHub Actions**
3. Create a workflow that publishes `website/` to GitHub Pages
4. Set custom domains in the repo settings
