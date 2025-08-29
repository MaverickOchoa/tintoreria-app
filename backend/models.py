from sqlalchemy import Column, Integer, String, Float, ForeignKey
from sqlalchemy.orm import relationship

# Importa la clase Base de la configuración de tu base de datos.
from .database import Base

# Modelos de la base de datos para SQLAlchemy

class Negocio(Base):
    """
    Modelo de la tabla 'negocios'
    Cada instancia de esta clase representa un negocio en el sistema.
    """
    __tablename__ = "negocios"

    id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String, unique=True, index=True)
    
    # Relaciones: Un negocio puede tener muchos usuarios, clientes y servicios.
    usuarios = relationship("Usuario", back_populates="negocio", cascade="all, delete-orphan")
    clientes = relationship("Cliente", back_populates="negocio", cascade="all, delete-orphan")
    servicios = relationship("Servicio", back_populates="negocio", cascade="all, delete-orphan")

class Usuario(Base):
    """
    Modelo de la tabla 'usuarios'
    Ahora incluye un rol y una relación con un negocio.
    """
    __tablename__ = "usuarios"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    
    # Nuevo campo para el rol del usuario (ej. 'admin', 'dueño', 'gerente', 'empleado')
    role = Column(String, default="empleado")
    
    # Nuevo campo para vincular el usuario a un negocio. Nullable para el admin.
    negocio_id = Column(Integer, ForeignKey("negocios.id"), nullable=True)
    negocio = relationship("Negocio", back_populates="usuarios")

class Cliente(Base):
    """
    Modelo de la tabla 'clientes'
    Ahora cada cliente debe estar asociado a un negocio específico.
    """
    __tablename__ = "clientes"

    id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String)
    apellido = Column(String)
    telefono = Column(String, nullable=True)
    email = Column(String, nullable=True)
    direccion = Column(String, nullable=True)
    
    # Relación: Cada cliente debe pertenecer a un negocio.
    negocio_id = Column(Integer, ForeignKey("negocios.id"), nullable=False)
    negocio = relationship("Negocio", back_populates="clientes")
    
    # Relación: Un cliente puede tener muchos servicios.
    servicios = relationship("Servicio", back_populates="cliente", cascade="all, delete-orphan")


class Servicio(Base):
    """
    Modelo de la tabla 'servicios'
    Ahora cada servicio debe estar asociado a un cliente Y a un negocio.
    """
    __tablename__ = "servicios"

    id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String)
    descripcion = Column(String, nullable=True)
    precio = Column(Float)
    
    # Relación: Cada servicio debe pertenecer a un cliente.
    cliente_id = Column(Integer, ForeignKey("clientes.id"), nullable=False)
    cliente = relationship("Cliente", back_populates="servicios")
    
    # Relación: Cada servicio debe pertenecer a un negocio.
    negocio_id = Column(Integer, ForeignKey("negocios.id"), nullable=False)
    negocio = relationship("Negocio", back_populates="servicios")
