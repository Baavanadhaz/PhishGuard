# app/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import Base, engine
from app.routes import auth_routes, history_routes, predict_routes

# ── Create all tables on startup ─────────────────────────────────────────────
Base.metadata.create_all(bind=engine)

# ── Application ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="ML-Based Phishing Website Detection API",
    description=(
        "Classify URLs as **safe** or **phishing** using heuristic ML features.\n\n"
        "### Quick start\n"
        "1. **Register** via `POST /auth/register`\n"
        "2. Click **Authorize 🔒** → enter your email as *username* and your password\n"
        "3. Use `POST /predict/` and `GET /history/`"
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS ─────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",   # Vite / React dev server
        "http://localhost:3000",   # CRA / Next.js dev server
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth_routes.router, prefix="/auth", tags=["Auth"])
app.include_router(predict_routes.router, tags=["Predict"])
app.include_router(history_routes.router, prefix="/history", tags=["History"])


# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/", tags=["Health"], summary="Health check")
def root():
    return {"status": "ok", "service": "Phishing Detection API"}
