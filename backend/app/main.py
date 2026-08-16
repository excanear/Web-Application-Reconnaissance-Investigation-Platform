from fastapi import FastAPI

app = FastAPI(title="Recon Platform API")


@app.get("/health")
def health():
    return {"status": "ok"}
