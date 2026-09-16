from app.database import engine
from models.base import Base
from models.security_log import SecurityLog
from models.security_alert import SecurityAlert


def init_database():
    Base.metadata.create_all(bind=engine)
    print("Database tables created successfully!")


if __name__ == "__main__":
    init_database()