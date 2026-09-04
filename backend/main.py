"""
Main FastAPI Application for SIH26106 Threat Platform.
Configures CORS, custom exception handlers, database lifecycle,
and loads seed investigations for immediate SOC demonstration.
"""
import os
import glob
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from .api.routes import router as api_router
from .database.database import init_db, SessionLocal
from .database import crud
from .services.pipeline import EmailAnalysisPipeline

MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "10"))
MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager: initializes tables and seeds sample investigations if empty."""
    init_db()

    # Pre-populate demo investigations if database is fresh
    db = SessionLocal()
    try:
        count = db.query(crud.Investigation).count()
        if count == 0:
            sample_dir = os.path.join(os.path.dirname(__file__), "sample_data")
            eml_files = glob.glob(os.path.join(sample_dir, "*.eml"))
            for eml_path in eml_files:
                try:
                    with open(eml_path, "rb") as f:
                        content = f.read()
                    fn = os.path.basename(eml_path)
                    pipeline = EmailAnalysisPipeline(raw_input=content, filename=fn, db=db)
                    pipeline.execute()
                except Exception:
                    pass
    finally:
        db.close()

    yield


app = FastAPI(
    title="SIH26106 AI-Powered Email Threat Detection & Forensics",
    description="Cybersecurity SOC platform for forensic email parsing, hop geolocation, URL heuristics, and explainable threat scoring.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Configuration
origins_env = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")
allow_origins = [orig.strip() for orig in origins_env.split(",") if orig.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global Exception Handlers for consistent API errors
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    detail = exc.detail
    if isinstance(detail, dict):
        code = detail.get("code", "HTTP_ERROR")
        message = detail.get("message", str(detail))
    else:
        code = "HTTP_ERROR"
        message = str(detail)

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "data": None,
            "error": {
                "code": code,
                "message": message
            }
        }
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "success": False,
            "data": None,
            "error": {
                "code": "VALIDATION_ERROR",
                "message": str(exc.errors())
            }
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "data": None,
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred in the forensic analysis pipeline."
            }
        }
    )


# Attach API router
app.include_router(api_router, prefix="/api")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
