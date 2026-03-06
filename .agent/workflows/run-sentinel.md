---
description: Run the Sentinel Project
---

This workflow starts the Sentinel project, which consists of a FastAPI backend and a React (Vite) frontend. 
You can run this workflow via the agent or manually.

// turbo-all

1. Start the FastAPI Backend
Run the following command with the CWD set to `e:\sentinel\Sentinel\sentinel_code\backend`
```powershell
pip install -r requirements.txt; uvicorn app.main:app --reload
```

2. Start the React Frontend
Run the following command with the CWD set to `e:\sentinel\Sentinel\frontend`
```powershell
npm install; npm run dev
```
