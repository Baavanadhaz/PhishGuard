 🛡️ PhishGuard AI

AI-Powered Phishing URL Detection System

PhishGuard AI is a full-stack web application that uses Machine Learning to analyze URLs and detect potential phishing threats.

The application allows users to securely register and log in, scan URLs in real time, view prediction confidence, understand the analysis reason, and access their previous scan history.

---

🚀 Features

- 🔍 Real-time URL phishing detection
- 🤖 Machine Learning-based URL classification
- 📊 Prediction confidence score
- 🛡️ Safe / Phishing classification
- 🔐 JWT-based user authentication
- 👤 User registration and login
- 📝 Personalized scan history
- 💾 Database storage for scan results
- ⚡ FastAPI REST API backend
- ⚛️ React + TypeScript frontend
- 🎨 Modern dark-themed responsive UI
- 🧠 URL feature extraction using `tldextract`
- 📦 Trained ML model saved using Joblib

---

 🏗️ System Architecture

text
                    ┌─────────────────────┐
                    │      User           │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  React + TypeScript │
                    │     Frontend        │
                    └──────────┬──────────┘
                               │
                         REST API
                               │
                               ▼
                    ┌─────────────────────┐
                    │      FastAPI        │
                    │      Backend        │
                    └──────────┬──────────┘
                               │
                 ┌─────────────┼─────────────┐
                 │             │             │
                 ▼             ▼             ▼
          ┌────────────┐ ┌────────────┐ ┌────────────┐
          │ JWT Auth   │ │ ML Model   │ │ Database   │
          └────────────┘ └─────┬──────┘ └────────────┘
                               │
                               ▼
                       ┌────────────────┐
                       │ URL Prediction │
                       │ Safe / Phishing│
                       └────────────────┘
