"""
Main FastAPI Application Entrypoint.
Provides CORS, API routing, database initialization, and static file mounting.
"""

from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.api.routes import router as api_router
from backend.database.db import init_db

ROOT_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = ROOT_DIR / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database tables on startup
    init_db()
    yield


app = FastAPI(
    title="Phishing Detection & Browser Protection API",
    description="Real-time AI & ML Powered Phishing Detection System",
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for Chrome Extension and Frontend Dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include core API routes under /api
app.include_router(api_router, prefix="/api")

# Mount frontend directory for browser access
if FRONTEND_DIR.exists():
    app.mount("/frontend", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
    app.mount("/dashboard", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="dashboard")
    app.mount("/src", StaticFiles(directory=str(FRONTEND_DIR / "src")), name="static_src")


@app.get("/Dashboard.html")
@app.get("/dashboard/Dashboard.html")
def get_dashboard_html():
    dashboard_path = FRONTEND_DIR / "Dashboard.html"
    if dashboard_path.exists():
        return FileResponse(str(dashboard_path))
    fallback = FRONTEND_DIR / "src" / "pages" / "Dashboard.html"
    return FileResponse(str(fallback))


@app.get("/")
def root():
    return {
        "system": "Phishing Detection AI Platform",
        "version": "1.0.0",
        "docs": "/docs",
        "dashboard": "/dashboard/Dashboard.html",
        "api_scan": "/api/scan",
        "api_metrics": "/api/metrics",
        "api_health": "/api/health"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
