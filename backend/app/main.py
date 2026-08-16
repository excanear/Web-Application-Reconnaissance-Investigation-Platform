from fastapi import FastAPI

from app.db import Base, engine
from app.routers import projects, scans

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Recon Platform API")
app.include_router(projects.router)
app.include_router(scans.router)


@app.get("/health")
def health():
    return {"status": "ok"}
