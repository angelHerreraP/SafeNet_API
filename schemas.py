from pydantic import BaseModel, EmailStr, UUID4
from typing import Optional, List
from datetime import datetime

class UsuarioBase(BaseModel):
    nombre: str
    email: EmailStr

class UsuarioCreate(UsuarioBase):
    password: str

class Usuario(UsuarioBase):
    id: UUID4
    fecha_registro: datetime
    activo: bool

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class ModuloBase(BaseModel):
    titulo: str
    descripcion: Optional[str] = None
    nivel: Optional[str] = None
    orden: Optional[int] = None
    visible: bool = True

class ModuloCreate(ModuloBase):
    pass

class Modulo(ModuloBase):
    id: int
    # Quitar la referencia circular para evitar errores de forward reference

    class Config:
        from_attributes = True



# Forward references para Pydantic


# Debe ir después de la definición de Reto

# --- OJO: Esto debe ir al final del archivo ---


class RetoBase(BaseModel):
    titulo: str
    descripcion: str
    solucion_hash: str
    puntos: Optional[int] = 10
    dificultad: Optional[str] = None

class RetoCreate(RetoBase):
    modulo_id: int

class Reto(RetoBase):
    id: int
    modulo_id: int

    class Config:
        from_attributes = True

class ProgresoUsuarioBase(BaseModel):
    completado: bool = False
    intentos: int = 0
    fecha_resuelto: Optional[datetime] = None

class ProgresoUsuarioCreate(ProgresoUsuarioBase):
    usuario_id: UUID4
    reto_id: int

class ProgresoUsuario(ProgresoUsuarioBase):
    id: int
    usuario_id: UUID4
    reto_id: int

    class Config:
        from_attributes = True

class FeedbackBase(BaseModel):
    mensaje: str

class FeedbackCreate(FeedbackBase):
    usuario_id: UUID4
    reto_id: int

class Feedback(FeedbackBase):
    id: int
    usuario_id: UUID4
    reto_id: int
    fecha: datetime

    class Config:
        from_attributes = True

class CertificacionBase(BaseModel):
    titulo: str
    hash_certificado: str

class CertificacionCreate(CertificacionBase):
    usuario_id: UUID4

class Certificacion(CertificacionBase):
    id: int
    usuario_id: UUID4
    fecha_emision: datetime

    class Config:
        from_attributes = True
