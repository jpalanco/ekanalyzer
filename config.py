

UPLOAD_FOLDER = "uploads/"
MAX_CONTENT_LENGTH= 16 * 1024 * 1024


CELERY_RESULT_BACKEND = "redis"
CELERY_REDIS_HOST = "localhost"
CELERY_REDIS_PORT = 6379
CELERY_REDIS_DB = 0

BROKER_URL = 'redis://localhost:6379/0'
MONGODB_SERVER = 'localhost'
MONGODB_PORT = 27017

f = open("user_agents.txt")
USER_AGENTS =  f.readlines()
