from fastapi import FastAPI, Depends, HTTPException, status, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from pydantic import BaseModel, ConfigDict
from passlib.context import CryptContext
from typing import Optional, Annotated, List
from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone

# Importa las clases de la base de datos y los modelos
from .database import SessionLocal, engine, Base
from . import models

# Configuración de la seguridad para contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Configuración del JWT
SECRET_KEY = "tu_clave_secreta_super_segura" # ¡CAMBIA ESTO EN PRODUCCIÓN!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Esquema para obtener el token desde el header de la solicitud
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Dependencia para manejar la sesión de la base de datos
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """
    Crea un token de acceso con una fecha de expiración.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_password(plain_password, hashed_password):
    """
    Verifica si una contraseña en texto plano coincide con su versión hasheada.
    """
    return pwd_context.verify(plain_password, hashed_password)

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    """
    Decodifica el token para obtener el usuario autenticado.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(models.Usuario).filter(models.Usuario.username == username).first()
    if user is None:
        raise credentials_exception
    return user


# Crea una instancia de la aplicación
app = FastAPI(
    title="Tintorería API",
    description="API para la gestión de clientes y servicios de una tintorería.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None,
    openapi_url="/openapi.json",
    swagger_ui_parameters={"oauth2RedirectUrl": "/oauth2-redirect"},
    security=[{"Bearer": []}],
    components={
        "securitySchemes": {
            "Bearer": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT"
            }
        }
    }
)

# Configuración de CORS
origins = [
    "http://localhost:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Modelos Pydantic para la entrada y salida de datos ---
class UserCreate(BaseModel):
    username: str
    password: str
    role: str

class InitialAdminUserCreate(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class ClienteBase(BaseModel):
    nombre: str
    apellido: str
    telefono: Optional[str] = None
    email: Optional[str] = None
    direccion: Optional[str] = None

class Cliente(ClienteBase):
    id: int
    negocio_id: int
    model_config = ConfigDict(from_attributes=True)

class ClienteUpdate(BaseModel):
    nombre: Optional[str] = None
    apellido: Optional[str] = None
    telefono: Optional[str] = None
    email: Optional[str] = None
    direccion: Optional[str] = None

class ServicioBase(BaseModel):
    nombre: str
    descripcion: Optional[str] = None
    precio: float
    cliente_id: int

class Servicio(ServicioBase):
    id: int
    negocio_id: int
    model_config = ConfigDict(from_attributes=True)

class ServicioUpdate(BaseModel):
    nombre: Optional[str] = None
    descripcion: Optional[str] = None
    precio: Optional[float] = None

class NegocioBase(BaseModel):
    nombre: str

class Negocio(NegocioBase):
    id: int
    model_config = ConfigDict(from_attributes=True)


# --- Endpoints de la API ---

@app.get("/")
def read_root():
    return {"message": "¡Hola desde el backend de la tintorería!"}

@app.post("/login", response_model=Token)
async def login_for_access_token(
    user_login: UserLogin,
    db: Session = Depends(get_db)
):
    # Busca el usuario en la base de datos
    db_user = db.query(models.Usuario).filter(models.Usuario.username == user_login.username).first()
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales incorrectas"
        )
    
    # Verifica la contraseña
    if not verify_password(user_login.password, db_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales incorrectas"
        )

    # Si todo es correcto, crea el token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": db_user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


# --- [NUEVOS ENDPOINTS] para Negocios y Usuarios ---

@app.post("/create-initial-admin", status_code=status.HTTP_201_CREATED)
def create_initial_admin(
    user_data: InitialAdminUserCreate,
    db: Session = Depends(get_db)
):
    """
    Crea el primer usuario administrador y un negocio inicial.
    Este endpoint solo funciona si no hay usuarios en la base de datos.
    """
    # Verifica si ya existe al menos un usuario
    if db.query(models.Usuario).first():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="El usuario inicial ya ha sido creado."
        )

    # Crea el negocio inicial
    negocio = models.Negocio(nombre="Mi Tintorería")
    db.add(negocio)
    db.commit()
    db.refresh(negocio)

    # Crea el usuario administrador, vinculado al negocio
    hashed_password = pwd_context.hash(user_data.password)
    admin_user = models.Usuario(
        username=user_data.username,
        hashed_password=hashed_password,
        role="admin",
        negocio_id=negocio.id
    )
    db.add(admin_user)
    db.commit()
    db.refresh(admin_user)

    return {"message": "Usuario administrador inicial y negocio creados exitosamente."}

@app.post("/negocios/", response_model=Negocio, status_code=status.HTTP_201_CREATED)
def create_negocio(
    negocio: NegocioBase,
    db: Session = Depends(get_db),
    # Solo los admins pueden crear nuevos negocios
    current_user: Annotated[models.Usuario, Depends(get_current_user)] = None
):
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Solo los administradores pueden crear negocios"
        )
    
    db_negocio = models.Negocio(**negocio.model_dump())
    db.add(db_negocio)
    db.commit()
    db.refresh(db_negocio)
    return db_negocio

@app.post("/negocios/{negocio_id}/users/", status_code=status.HTTP_201_CREATED)
def create_user_for_negocio(
    negocio_id: int,
    user: UserCreate,
    db: Session = Depends(get_db),
    current_user: Annotated[models.Usuario, Depends(get_current_user)] = None
):
    # Verifica que el usuario tenga permisos para crear usuarios en este negocio
    if current_user.role not in ["admin", "dueno"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Solo los dueños y administradores pueden crear usuarios"
        )
    if current_user.role == "dueno" and current_user.negocio_id != negocio_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes permiso para crear usuarios en este negocio"
        )

    db_user = db.query(models.Usuario).filter(models.Usuario.username == user.username).first()
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El nombre de usuario ya está registrado."
        )

    hashed_password = pwd_context.hash(user.password)
    db_user = models.Usuario(
        username=user.username,
        hashed_password=hashed_password,
        role=user.role,
        negocio_id=negocio_id
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return {"message": "Usuario creado exitosamente"}

# --- [MODIFICADOS] Endpoints para Clientes ---

@app.post("/negocios/{negocio_id}/clientes/", response_model=Cliente)
def create_cliente(
    negocio_id: int,
    cliente: ClienteBase, 
    db: Session = Depends(get_db), 
    current_user: Annotated[models.Usuario, Depends(get_current_user)] = None
):
    if current_user.negocio_id != negocio_id and current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acceso denegado")
    
    db_cliente = models.Cliente(**cliente.model_dump(), negocio_id=negocio_id)
    db.add(db_cliente)
    db.commit()
    db.refresh(db_cliente)
    return db_cliente

@app.get("/negocios/{negocio_id}/clientes/", response_model=List[Cliente])
def read_clientes(
    negocio_id: int,
    db: Session = Depends(get_db),
    current_user: Annotated[models.Usuario, Depends(get_current_user)] = None
):
    if current_user.negocio_id != negocio_id and current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acceso denegado")
        
    clientes = db.query(models.Cliente).filter(models.Cliente.negocio_id == negocio_id).all()
    return clientes

@app.get("/negocios/{negocio_id}/clientes/{cliente_id}", response_model=Cliente)
def read_cliente(
    negocio_id: int,
    cliente_id: int,
    db: Session = Depends(get_db),
    current_user: Annotated[models.Usuario, Depends(get_current_user)] = None
):
    if current_user.negocio_id != negocio_id and current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acceso denegado")
    
    db_cliente = db.query(models.Cliente).filter(
        models.Cliente.id == cliente_id,
        models.Cliente.negocio_id == negocio_id
    ).first()
    if db_cliente is None:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")
    return db_cliente

@app.patch("/negocios/{negocio_id}/clientes/{cliente_id}", response_model=Cliente)
def update_cliente(
    negocio_id: int,
    cliente_id: int,
    cliente: ClienteUpdate,
    db: Session = Depends(get_db),
    current_user: Annotated[models.Usuario, Depends(get_current_user)] = None
):
    if current_user.negocio_id != negocio_id and current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acceso denegado")

    db_cliente = db.query(models.Cliente).filter(
        models.Cliente.id == cliente_id,
        models.Cliente.negocio_id == negocio_id
    ).first()
    if db_cliente is None:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")
    
    update_data = cliente.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_cliente, key, value)
    
    db.commit()
    db.refresh(db_cliente)
    return db_cliente

@app.delete("/negocios/{negocio_id}/clientes/{cliente_id}")
def delete_cliente(
    negocio_id: int,
    cliente_id: int,
    db: Session = Depends(get_db),
    current_user: Annotated[models.Usuario, Depends(get_current_user)] = None
):
    if current_user.negocio_id != negocio_id and current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acceso denegado")
    
    db_cliente = db.query(models.Cliente).filter(
        models.Cliente.id == cliente_id,
        models.Cliente.negocio_id == negocio_id
    ).first()
    if db_cliente is None:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")
    
    db.delete(db_cliente)
    db.commit()
    return {"message": "Cliente eliminado exitosamente"}


# --- [MODIFICADOS] Endpoints para Servicios ---

@app. post("/negocios/{negocio_id}/servicios/", response_model=Servicio, status_code=status.HTTP_201_CREATED)
def create_servicio(
    negocio_id: int,
    servicio: ServicioBase,
    db: Session = Depends(get_db),
    current_user: Annotated[models.Usuario, Depends(get_current_user)] = None
):
    if current_user.negocio_id != negocio_id and current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acceso denegado")

    # Verifica que el cliente exista y pertenezca al mismo negocio
    cliente = db.query(models.Cliente).filter(
        models.Cliente.id == servicio.cliente_id,
        models.Cliente.negocio_id == negocio_id
    ).first()
    if cliente is None:
        raise HTTPException(status_code=404, detail="Cliente no encontrado o no pertenece a este negocio")

    db_servicio = models.Servicio(**servicio.model_dump(), negocio_id=negocio_id)
    db.add(db_servicio)
    db.commit()
    db.refresh(db_servicio)
    return db_servicio

@app.get("/negocios/{negocio_id}/servicios/{servicio_id}", response_model=Servicio)
def read_servicio(
    negocio_id: int,
    servicio_id: int,
    db: Session = Depends(get_db),
    current_user: Annotated[models.Usuario, Depends(get_current_user)] = None
):
    if current_user.negocio_id != negocio_id and current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acceso denegado")
    
    db_servicio = db.query(models.Servicio).filter(
        models.Servicio.id == servicio_id,
        models.Servicio.negocio_id == negocio_id
    ).first()
    if db_servicio is None:
        raise HTTPException(status_code=404, detail="Servicio no encontrado")
    return db_servicio

@app.patch("/negocios/{negocio_id}/servicios/{servicio_id}", response_model=Servicio)
def update_servicio(
    negocio_id: int,
    servicio_id: int,
    servicio: ServicioUpdate,
    db: Session = Depends(get_db),
    current_user: Annotated[models.Usuario, Depends(get_current_user)] = None
):
    if current_user.negocio_id != negocio_id and current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acceso denegado")

    db_servicio = db.query(models.Servicio).filter(
        models.Servicio.id == servicio_id,
        models.Servicio.negocio_id == negocio_id
    ).first()
    if db_servicio is None:
        raise HTTPException(status_code=404, detail="Servicio no encontrado")
    
    update_data = servicio.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_servicio, key, value)
    
    db.commit()
    db.refresh(db_servicio)
    return db_servicio

@app.delete("/negocios/{negocio_id}/servicios/{servicio_id}")
def delete_servicio(
    negocio_id: int,
    servicio_id: int,
    db: Session = Depends(get_db),
    current_user: Annotated[models.Usuario, Depends(get_current_user)] = None
):
    if current_user.negocio_id != negocio_id and current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acceso denegado")
    
    db_servicio = db.query(models.Servicio).filter(
        models.Servicio.id == servicio_id,
        models.Servicio.negocio_id == negocio_id
    ).first()
    if db_servicio is None:
        raise HTTPException(status_code=404, detail="Servicio no encontrado")
    
    db.delete(db_servicio)
    db.commit()
    return {"message": "Servicio eliminado exitosamente"}


# El código para crear las tablas debe ir aquí
# Esto asegura que `Base` esté completamente cargado antes de ser usado.
Base.metadata.create_all(bind=engine)
