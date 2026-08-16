import os

from celery import Celery

from app.config import settings

celery_app = Celery("recon", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.task_always_eager = (
    os.getenv("CELERY_TASK_ALWAYS_EAGER", "false").lower() == "true"
)
