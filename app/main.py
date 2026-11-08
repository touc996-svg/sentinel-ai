from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.events import router as events_router
from app.config import APP_NAME, APP_VERSION
from app.database import get_db, init_db


def create_app(initialize_database: bool = True) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if initialize_database:
            init_db()
        yield

    application = FastAPI(
        title=APP_NAME,
        version=APP_VERSION,
        description=(
            "Defensive cybersecurity event ingestion and "
            "threat detection platform."
        ),
        lifespan=lifespan,
    )

    application.include_router(events_router)

    @application.get("/")
    def root():
        return {
            "name": APP_NAME,
            "version": APP_VERSION,
            "status": "running",
        }

    @application.get("/health")
    def health(db: Session = Depends(get_db)):
        db.execute(text("SELECT 1"))
        return {
            "status": "healthy",
            "database": "connected",
        }

    return application


app = create_app()
