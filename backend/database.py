from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# URL de la base de datos. Usa SQLite para simplicidad.
SQLALCHEMY_DATABASE_URL = "sqlite:///./sql_app.db"

# Crea el motor de la base de datos.
# `check_same_thread=False` es necesario solo para SQLite.
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

# Crea una clase de sesión local.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Crea la base declarativa, que usaremos en `models.py`
Base = declarative_base()
