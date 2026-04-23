# ThreatWatch — AI Security Dashboard

## Repo Structure (flat — no backend/ subfolder)
```
ThreatWatch/
├── Dockerfile          ← Railway reads this
├── main.py             ← FastAPI backend
├── requirements.txt    ← Python dependencies
├── forwarder.py        ← Run on Ubuntu to ship alerts
├── .env.example        ← Copy to .env locally
├── .gitignore
└── frontend/           ← Vercel deploys this
    ├── index.html
    ├── package.json
    ├── vite.config.js
    ├── vercel.json
    └── src/
        ├── App.jsx
        ├── main.jsx
        └── index.css
```

## Deploy Backend to Railway

1. Create new GitHub repo, push all files
2. Go to https://railway.app → New Project → Deploy from GitHub
3. Select your repo
4. Railway auto-detects Dockerfile at root
5. Settings:
   - Root Directory: leave BLANK
   - Dockerfile Path: leave BLANK
   - Port: 8000
6. Add Variables:
   - OPENAI_API_KEY=sk-...
7. Railway gives you: https://your-app.up.railway.app
8. Visit https://your-app.up.railway.app/alerts — should show mock data JSON

## Deploy Frontend to Vercel

1. Go to https://vercel.com → New Project → import same repo
2. Settings:
   - Root Directory: `frontend`
   - Framework: Vite
3. IMPORTANT: Edit `frontend/src/App.jsx` line 13:
   ```js
   const API = 'https://your-app.up.railway.app'
   ```
4. Push change → Vercel auto-deploys

## Run Forwarder on Ubuntu

1. Edit `forwarder.py` line 7 — set your Railway URL
2. Run:
   ```bash
   pip install requests
   python3 forwarder.py &
   ```

## Local Development

```bash
# Backend
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Frontend
cd frontend
npm install
npm run dev
```
