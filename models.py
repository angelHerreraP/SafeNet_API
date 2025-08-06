from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, Text, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base
import uuid

class Usuario(Base):
    __tablename__ = "usuarios"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nombre = Column(String(100), nullable=False)
    email = Column(String(150), unique=True, nullable=False)
    password_hash = Column(Text, nullable=False)
    rol = Column(String(20), default="estudiante")
    fecha_registro = Column(DateTime, server_default=func.now())
    activo = Column(Boolean, default=True)
    retos = relationship("ProgresoUsuario", back_populates="usuario")
    feedbacks = relationship("Feedback", back_populates="usuario")
    certificaciones = relationship("Certificacion", back_populates="usuario")
    auditorias = relationship("Auditoria", back_populates="usuario")
    sesiones = relationship("SesionJWT", back_populates="usuario")
    sesiones_laboratorio = relationship("SesionLaboratorio", back_populates="usuario")

class Modulo(Base):
    __tablename__ = "modulos"
    id = Column(Integer, primary_key=True, index=True)
    titulo = Column(String(100), nullable=False)
    descripcion = Column(Text)
    nivel = Column(String(20))
    orden = Column(Integer)
    visible = Column(Boolean, default=True)
    retos = relationship("Reto", back_populates="modulo")

class Reto(Base):
    __tablename__ = "retos"
    id = Column(Integer, primary_key=True, index=True)
    modulo_id = Column(Integer, ForeignKey("modulos.id", ondelete="CASCADE"))
    titulo = Column(String(100), nullable=False)
    descripcion = Column(Text, nullable=False)
    solucion_hash = Column(Text, nullable=False)
    puntos = Column(Integer, default=10)
    dificultad = Column(String(20))
    modulo = relationship("Modulo", back_populates="retos")
    progresos = relationship("ProgresoUsuario", back_populates="reto")
    feedbacks = relationship("Feedback", back_populates="reto")

class ProgresoUsuario(Base):
    __tablename__ = "progreso_usuarios"
    id = Column(Integer, primary_key=True, index=True)
    usuario_id = Column(UUID(as_uuid=True), ForeignKey("usuarios.id", ondelete="CASCADE"))
    reto_id = Column(Integer, ForeignKey("retos.id", ondelete="CASCADE"))
    completado = Column(Boolean, default=False)
    intentos = Column(Integer, default=0)
    fecha_resuelto = Column(DateTime)
    usuario = relationship("Usuario", back_populates="retos")
    reto = relationship("Reto", back_populates="progresos")

class Feedback(Base):
    __tablename__ = "feedback"
    id = Column(Integer, primary_key=True, index=True)
    usuario_id = Column(UUID(as_uuid=True), ForeignKey("usuarios.id", ondelete="CASCADE"))
    reto_id = Column(Integer, ForeignKey("retos.id", ondelete="SET NULL"))
    mensaje = Column(Text)
    fecha = Column(DateTime, server_default=func.now())
    usuario = relationship("Usuario", back_populates="feedbacks")
    reto = relationship("Reto", back_populates="feedbacks")

class Certificacion(Base):
    __tablename__ = "certificaciones"
    id = Column(Integer, primary_key=True, index=True)
    usuario_id = Column(UUID(as_uuid=True), ForeignKey("usuarios.id", ondelete="CASCADE"))
    titulo = Column(String(100))
    fecha_emision = Column(DateTime, server_default=func.now())
    hash_certificado = Column(Text, unique=True)
    usuario = relationship("Usuario", back_populates="certificaciones")

class Auditoria(Base):
    __tablename__ = "auditoria"
    id = Column(Integer, primary_key=True, index=True)
    usuario_id = Column(UUID(as_uuid=True), ForeignKey("usuarios.id", ondelete="SET NULL"))
    accion = Column(Text)
    fecha = Column(DateTime, server_default=func.now())
    ip = Column(Text)
    usuario = relationship("Usuario", back_populates="auditorias")

class SesionJWT(Base):
    __tablename__ = "sesiones_jwt"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    usuario_id = Column(UUID(as_uuid=True), ForeignKey("usuarios.id", ondelete="CASCADE"))
    jwt_token = Column(Text, nullable=False)
    fecha_creacion = Column(DateTime, server_default=func.now())
    expiracion = Column(DateTime)
    usuario = relationship("Usuario", back_populates="sesiones")

class SesionLaboratorio(Base):
    __tablename__ = "sesiones_laboratorio"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    usuario_id = Column(UUID(as_uuid=True), ForeignKey("usuarios.id", ondelete="CASCADE"), nullable=False)
    laboratorio_id = Column(Integer, nullable=False)
    fecha_inicio = Column(DateTime, nullable=False)
    fecha_fin = Column(DateTime)
    estado = Column(String(20), nullable=False, default="activa")
    avance = Column(JSON)
    tiempo_limite = Column(Integer, nullable=False)
    usuario = relationship("Usuario", back_populates="sesiones_laboratorio")
