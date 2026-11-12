#!/usr/bin/env bash
# Run from the root of your local clone of jaycash988/telemetrytreathanlysis,
# after copying these files over the ones in the repo.
set -e
git pull --rebase origin main || true
# remove stray/old files if they exist
git rm -f --ignore-unmatch a "telemetry-threat-analysis-ready-to-deploy (8).zip" >/dev/null
git add app.py analyze.py schema.sql render.yaml requirements.txt README.md .gitignore
git commit -m "Log to Supabase Postgres (events table); add schema, Render config, DB timeouts" || echo "nothing new to commit"
git push origin main
echo; echo "Pushed. Render auto-deploys if auto-deploy is on; otherwise click Manual Deploy."
git log --oneline -3
