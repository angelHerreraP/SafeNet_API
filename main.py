from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import models, schemas
from database import engine, get_db
import os
from dotenv import load_dotenv
from fastapi import APIRouter
from sqlalchemy.exc import SQLAlchemyError
from schemas import SesionLaboratorio, SesionLaboratorioCreate, SesionLaboratorioUpdate
from models import SesionLaboratorio as SesionLaboratorioModel
from uuid import UUID
from typing import List

load_dotenv()
models.Base.metadata.create_all(bind=engine)

app = FastAPI()
# Configuración de CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Cambia esto por tu dominio frontend en producción
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(models.Usuario).filter(models.Usuario.email == email).first()
    if user is None:
        raise credentials_exception
    return user


# Auth
@app.post("/token", response_model=schemas.Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # Validar campos manualmente para evitar error de validación de Pydantic
    if not getattr(form_data, "username", None) or not getattr(form_data, "password", None):
        raise HTTPException(status_code=400, detail="Email y contraseña son requeridos")
    user = db.query(models.Usuario).filter(models.Usuario.email == form_data.username).first()
    if not user:
        raise HTTPException(status_code=400, detail="Usuario no existe")
    if not user.activo:
        raise HTTPException(status_code=403, detail="Usuario inactivo")
    if not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Contraseña incorrecta")
    access_token = create_access_token(data={"sub": user.email}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

# Alias para /login (acepta el mismo body que /token)
@app.post("/login", response_model=schemas.Token)
def login_alias(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    return login_for_access_token(form_data, db)

# Alias para /register (acepta el mismo body que /usuarios/)
from fastapi import Request
from fastapi.responses import JSONResponse

@app.post("/register", response_model=schemas.Usuario)
async def register_alias(usuario: schemas.UsuarioCreate, db: Session = Depends(get_db)):
    db_usuario = create_usuario(usuario, db)
    return schemas.Usuario.from_orm(db_usuario)

# Permitir preflight para /register (CORS)
@app.options("/register")
async def options_register(request: Request):
    return JSONResponse(status_code=200, content={})

# Usuarios

# --- USUARIOS CRUD ---
@app.post("/usuarios/", response_model=schemas.Usuario)
def create_usuario(usuario: schemas.UsuarioCreate, db: Session = Depends(get_db)):
    db_usuario = db.query(models.Usuario).filter(models.Usuario.email == usuario.email).first()
    if db_usuario:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(usuario.password)
    db_usuario = models.Usuario(
        nombre=usuario.nombre,
        email=usuario.email,
        password_hash=hashed_password,
        rol="estudiante"
    )
    db.add(db_usuario)
    db.commit()
    db.refresh(db_usuario)
    return db_usuario

@app.get("/usuarios/", response_model=list[schemas.Usuario])
def list_usuarios(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    usuarios = db.query(models.Usuario).offset(skip).limit(limit).all()
    return [schemas.Usuario.from_orm(u) for u in usuarios]

@app.get("/usuarios/{usuario_id}", response_model=schemas.Usuario)
def get_usuario(usuario_id: str, db: Session = Depends(get_db)):
    usuario = db.query(models.Usuario).filter(models.Usuario.id == usuario_id).first()
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuario not found")
    return schemas.Usuario.from_orm(usuario)

@app.put("/usuarios/{usuario_id}", response_model=schemas.Usuario)
def update_usuario(usuario_id: str, usuario: schemas.UsuarioCreate, db: Session = Depends(get_db), user: models.Usuario = Depends(get_current_user)):
    db_usuario = db.query(models.Usuario).filter(models.Usuario.id == usuario_id).first()
    if not db_usuario:
        raise HTTPException(status_code=404, detail="Usuario not found")
    db_usuario.nombre = usuario.nombre
    db_usuario.email = usuario.email
    db_usuario.rol = usuario.rol
    db_usuario.password_hash = get_password_hash(usuario.password)
    db.commit()
    db.refresh(db_usuario)
    return schemas.Usuario.from_orm(db_usuario)

@app.delete("/usuarios/{usuario_id}")
def delete_usuario(usuario_id: str, db: Session = Depends(get_db), user: models.Usuario = Depends(get_current_user)):
    db_usuario = db.query(models.Usuario).filter(models.Usuario.id == usuario_id).first()
    if not db_usuario:
        raise HTTPException(status_code=404, detail="Usuario not found")
    db.delete(db_usuario)
    db.commit()
    return {"ok": True}

# Módulos

# --- MODULOS CRUD ---
@app.post("/modulos/", response_model=schemas.Modulo)
def create_modulo(modulo: schemas.ModuloCreate, db: Session = Depends(get_db), user: models.Usuario = Depends(get_current_user)):
    db_modulo = models.Modulo(**modulo.dict())
    db.add(db_modulo)
    db.commit()
    db.refresh(db_modulo)
    return schemas.Modulo.from_orm(db_modulo)

@app.get("/modulos/", response_model=list[schemas.Modulo])
def list_modulos(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    modulos = db.query(models.Modulo).offset(skip).limit(limit).all()
    return [schemas.Modulo.from_orm(m) for m in modulos]

@app.get("/modulos/{modulo_id}", response_model=schemas.Modulo)
def get_modulo(modulo_id: int, db: Session = Depends(get_db)):
    modulo = db.query(models.Modulo).filter(models.Modulo.id == modulo_id).first()
    if not modulo:
        raise HTTPException(status_code=404, detail="Modulo not found")
    return schemas.Modulo.from_orm(modulo)

@app.put("/modulos/{modulo_id}", response_model=schemas.Modulo)
def update_modulo(modulo_id: int, modulo: schemas.ModuloCreate, db: Session = Depends(get_db), user: models.Usuario = Depends(get_current_user)):
    db_modulo = db.query(models.Modulo).filter(models.Modulo.id == modulo_id).first()
    if not db_modulo:
        raise HTTPException(status_code=404, detail="Modulo not found")
    for k, v in modulo.dict().items():
        setattr(db_modulo, k, v)
    db.commit()
    db.refresh(db_modulo)
    return schemas.Modulo.from_orm(db_modulo)

@app.post("/retos/", response_model=schemas.Reto)
def create_reto(reto: schemas.RetoCreate, db: Session = Depends(get_db), user: models.Usuario = Depends(get_current_user)):
    db_reto = models.Reto(**reto.dict())
    db.add(db_reto)
    db.commit()
    db.refresh(db_reto)
    return schemas.Reto.from_orm(db_reto)

@app.get("/retos/", response_model=list[schemas.Reto])
def list_retos(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    retos = db.query(models.Reto).offset(skip).limit(limit).all()
    return [schemas.Reto.from_orm(r) for r in retos]

@app.get("/retos/{reto_id}", response_model=schemas.Reto)
def get_reto(reto_id: int, db: Session = Depends(get_db)):
    reto = db.query(models.Reto).filter(models.Reto.id == reto_id).first()
    if not reto:
        raise HTTPException(status_code=404, detail="Reto not found")
    return schemas.Reto.from_orm(reto)

@app.put("/retos/{reto_id}", response_model=schemas.Reto)
def update_reto(reto_id: int, reto: schemas.RetoCreate, db: Session = Depends(get_db), user: models.Usuario = Depends(get_current_user)):
    db_reto = db.query(models.Reto).filter(models.Reto.id == reto_id).first()
    if not db_reto:
        raise HTTPException(status_code=404, detail="Reto not found")
    for k, v in reto.dict().items():
        setattr(db_reto, k, v)
    db.commit()
    db.refresh(db_reto)
    return schemas.Reto.from_orm(db_reto)

@app.post("/progreso/", response_model=schemas.ProgresoUsuario)
def create_progreso(progreso: schemas.ProgresoUsuarioCreate, db: Session = Depends(get_db), user: models.Usuario = Depends(get_current_user)):
    db_progreso = models.ProgresoUsuario(**progreso.dict())
    db.add(db_progreso)
    db.commit()
    db.refresh(db_progreso)
    return schemas.ProgresoUsuario.from_orm(db_progreso)

@app.get("/progreso/", response_model=list[schemas.ProgresoUsuario])
def list_progreso(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    progresos = db.query(models.ProgresoUsuario).offset(skip).limit(limit).all()
    return [schemas.ProgresoUsuario.from_orm(p) for p in progresos]

@app.get("/progreso/{progreso_id}", response_model=schemas.ProgresoUsuario)
def get_progreso(progreso_id: int, db: Session = Depends(get_db)):
    progreso = db.query(models.ProgresoUsuario).filter(models.ProgresoUsuario.id == progreso_id).first()
    if not progreso:
        raise HTTPException(status_code=404, detail="Progreso not found")
    return schemas.ProgresoUsuario.from_orm(progreso)

@app.put("/progreso/{progreso_id}", response_model=schemas.ProgresoUsuario)
def update_progreso(progreso_id: int, progreso: schemas.ProgresoUsuarioCreate, db: Session = Depends(get_db), user: models.Usuario = Depends(get_current_user)):
    db_progreso = db.query(models.ProgresoUsuario).filter(models.ProgresoUsuario.id == progreso_id).first()
    if not db_progreso:
        raise HTTPException(status_code=404, detail="Progreso not found")
    for k, v in progreso.dict().items():
        setattr(db_progreso, k, v)
    db.commit()
    db.refresh(db_progreso)
    return schemas.ProgresoUsuario.from_orm(db_progreso)

@app.post("/feedback/", response_model=schemas.Feedback)
def create_feedback(feedback: schemas.FeedbackCreate, db: Session = Depends(get_db), user: models.Usuario = Depends(get_current_user)):
    db_feedback = models.Feedback(**feedback.dict())
    db.add(db_feedback)
    db.commit()
    db.refresh(db_feedback)
    return schemas.Feedback.from_orm(db_feedback)

@app.get("/feedback/", response_model=list[schemas.Feedback])
def list_feedback(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    feedbacks = db.query(models.Feedback).offset(skip).limit(limit).all()
    return [schemas.Feedback.from_orm(f) for f in feedbacks]

@app.get("/feedback/{feedback_id}", response_model=schemas.Feedback)
def get_feedback(feedback_id: int, db: Session = Depends(get_db)):
    feedback = db.query(models.Feedback).filter(models.Feedback.id == feedback_id).first()
    if not feedback:
        raise HTTPException(status_code=404, detail="Feedback not found")
    return schemas.Feedback.from_orm(feedback)

@app.put("/feedback/{feedback_id}", response_model=schemas.Feedback)
def update_feedback(feedback_id: int, feedback: schemas.FeedbackCreate, db: Session = Depends(get_db), user: models.Usuario = Depends(get_current_user)):
    db_feedback = db.query(models.Feedback).filter(models.Feedback.id == feedback_id).first()
    if not db_feedback:
        raise HTTPException(status_code=404, detail="Feedback not found")
    for k, v in feedback.dict().items():
        setattr(db_feedback, k, v)
    db.commit()
    db.refresh(db_feedback)
    return schemas.Feedback.from_orm(db_feedback)

@app.post("/certificaciones/", response_model=schemas.Certificacion)
def create_certificacion(cert: schemas.CertificacionCreate, db: Session = Depends(get_db), user: models.Usuario = Depends(get_current_user)):
    db_cert = models.Certificacion(**cert.dict())
    db.add(db_cert)
    db.commit()
    db.refresh(db_cert)
    return schemas.Certificacion.from_orm(db_cert)

@app.get("/certificaciones/", response_model=list[schemas.Certificacion])
def list_certificaciones(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    certs = db.query(models.Certificacion).offset(skip).limit(limit).all()
    return [schemas.Certificacion.from_orm(c) for c in certs]

@app.get("/certificaciones/{certificacion_id}", response_model=schemas.Certificacion)
def get_certificacion(certificacion_id: int, db: Session = Depends(get_db)):
    cert = db.query(models.Certificacion).filter(models.Certificacion.id == certificacion_id).first()
    if not cert:
        raise HTTPException(status_code=404, detail="Certificacion not found")
    return schemas.Certificacion.from_orm(cert)

@app.put("/certificaciones/{certificacion_id}", response_model=schemas.Certificacion)
def update_certificacion(certificacion_id: int, cert: schemas.CertificacionCreate, db: Session = Depends(get_db), user: models.Usuario = Depends(get_current_user)):
    db_cert = db.query(models.Certificacion).filter(models.Certificacion.id == certificacion_id).first()
    if not db_cert:
        raise HTTPException(status_code=404, detail="Certificacion not found")
    for k, v in cert.dict().items():
        setattr(db_cert, k, v)
    db.commit()
    db.refresh(db_cert)
    return schemas.Certificacion.from_orm(db_cert)

# --- SESIONES DE LABORATORIO ---
lab_router = APIRouter()

@lab_router.post("/sesiones_laboratorio/", response_model=SesionLaboratorio)
def crear_sesion_laboratorio(sesion: SesionLaboratorioCreate, db: Session = Depends(get_db), user: models.Usuario = Depends(get_current_user)):
    sesion_existente = db.query(SesionLaboratorioModel).filter(
        SesionLaboratorioModel.usuario_id == user.id,
        SesionLaboratorioModel.laboratorio_id == sesion.laboratorio_id,
        SesionLaboratorioModel.estado == "activa"
    ).first()
    if sesion_existente:
        raise HTTPException(status_code=400, detail="Ya existe una sesión activa para este laboratorio")
    nueva_sesion = SesionLaboratorioModel(
        usuario_id=user.id,
        laboratorio_id=sesion.laboratorio_id,
        fecha_inicio=datetime.utcnow(),
        estado="activa",
        tiempo_limite=sesion.tiempo_limite
    )
    db.add(nueva_sesion)
    db.commit()
    db.refresh(nueva_sesion)
    return SesionLaboratorio.from_orm(nueva_sesion)

@lab_router.get("/sesiones_laboratorio/{sesion_id}", response_model=SesionLaboratorio)
def obtener_sesion_laboratorio(sesion_id: UUID, db: Session = Depends(get_db), user: models.Usuario = Depends(get_current_user)):
    sesion = db.query(SesionLaboratorioModel).filter(SesionLaboratorioModel.id == sesion_id, SesionLaboratorioModel.usuario_id == user.id).first()
    if not sesion:
        raise HTTPException(status_code=404, detail="Sesión no encontrada")
    return SesionLaboratorio.from_orm(sesion)

@lab_router.put("/sesiones_laboratorio/{sesion_id}/avance", response_model=SesionLaboratorio)
def actualizar_avance_sesion(sesion_id: UUID, avance: SesionLaboratorioUpdate, db: Session = Depends(get_db), user: models.Usuario = Depends(get_current_user)):
    sesion = db.query(SesionLaboratorioModel).filter(SesionLaboratorioModel.id == sesion_id, SesionLaboratorioModel.usuario_id == user.id).first()
    if not sesion:
        raise HTTPException(status_code=404, detail="Sesión no encontrada")
    if sesion.estado != "activa":
        raise HTTPException(status_code=400, detail="No se puede actualizar una sesión no activa")
    if avance.avance is not None:
        sesion.avance = avance.avance
    db.commit()
    db.refresh(sesion)
    return SesionLaboratorio.from_orm(sesion)

@lab_router.post("/sesiones_laboratorio/{sesion_id}/finalizar", response_model=SesionLaboratorio)
def finalizar_sesion_laboratorio(sesion_id: UUID, db: Session = Depends(get_db), user: models.Usuario = Depends(get_current_user)):
    sesion = db.query(SesionLaboratorioModel).filter(SesionLaboratorioModel.id == sesion_id, SesionLaboratorioModel.usuario_id == user.id).first()
    if not sesion:
        raise HTTPException(status_code=404, detail="Sesión no encontrada")
    if sesion.estado != "activa":
        raise HTTPException(status_code=400, detail="La sesión ya está finalizada o expirada")
    sesion.estado = "completada"
    sesion.fecha_fin = datetime.utcnow()
    db.commit()
    db.refresh(sesion)
    return SesionLaboratorio.from_orm(sesion)

@lab_router.post("/sesiones_laboratorio/{sesion_id}/expirar", response_model=SesionLaboratorio)
def expirar_sesion_laboratorio(sesion_id: UUID, db: Session = Depends(get_db), user: models.Usuario = Depends(get_current_user)):
    sesion = db.query(SesionLaboratorioModel).filter(SesionLaboratorioModel.id == sesion_id, SesionLaboratorioModel.usuario_id == user.id).first()
    if not sesion:
        raise HTTPException(status_code=404, detail="Sesión no encontrada")
    if sesion.estado != "activa":
        raise HTTPException(status_code=400, detail="La sesión ya está finalizada o expirada")
    sesion.estado = "expirada"
    sesion.fecha_fin = datetime.utcnow()
    sesion.avance = None  # Eliminar avance
    db.commit()
    db.refresh(sesion)
    return SesionLaboratorio.from_orm(sesion)

@lab_router.delete("/sesiones_laboratorio/{sesion_id}")
def eliminar_sesion_laboratorio(sesion_id: UUID, db: Session = Depends(get_db), user: models.Usuario = Depends(get_current_user)):
    sesion = db.query(SesionLaboratorioModel).filter(SesionLaboratorioModel.id == sesion_id, SesionLaboratorioModel.usuario_id == user.id).first()
    if not sesion:
        raise HTTPException(status_code=404, detail="Sesión no encontrada")
    db.delete(sesion)
    db.commit()
    return {"ok": True}

@lab_router.post("/labs/start")
def lanzar_laboratorio(sesion: SesionLaboratorioCreate, db: Session = Depends(get_db), user: models.Usuario = Depends(get_current_user)):
    LAB_URL = "https://glittering-taffy-a43665.netlify.app/"
    sesion_existente = db.query(SesionLaboratorioModel).filter(
        SesionLaboratorioModel.usuario_id == user.id,
        SesionLaboratorioModel.laboratorio_id == sesion.laboratorio_id,
        SesionLaboratorioModel.estado == "activa"
    ).first()
    if sesion_existente:
        session_id = sesion_existente.id
    else:
        nueva_sesion = SesionLaboratorioModel(
            usuario_id=user.id,
            laboratorio_id=sesion.laboratorio_id,
            fecha_inicio=datetime.utcnow(),
            estado="activa",
            tiempo_limite=sesion.tiempo_limite
        )
        db.add(nueva_sesion)
        db.commit()
        db.refresh(nueva_sesion)
        session_id = nueva_sesion.id
    url = f"{LAB_URL}?session_id={session_id}"
    return {"url": url, "session_id": str(session_id)}

app.include_router(lab_router)
