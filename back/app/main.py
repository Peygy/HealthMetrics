from fastapi import FastAPI, HTTPException, Depends, status
from sqlalchemy import ForeignKey, create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from typing import List
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import jwt
from fastapi.openapi.utils import get_openapi
from fastapi.security import OAuth2PasswordBearer
from statistics import mean
from fastapi.responses import StreamingResponse
import matplotlib.pyplot as plt
import io
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Health Monitoring API",
        version="1.0.0",
        description="API для мониторинга здоровья пользователей",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
    }
    for path in openapi_schema["paths"]:
        for method in openapi_schema["paths"][path]:
            openapi_schema["paths"][path][method]["security"] = [{"BearerAuth": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

SQLALCHEMY_DATABASE_URL = "sqlite:///./app.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class UserDB(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    age = Column(Integer)
    gender = Column(String)

class HealthDataDB(Base):
    __tablename__ = "health_data"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    heart_rate = Column(Integer)
    blood_pressure = Column(String)
    oxygen_level = Column(Integer)
    weight = Column(Float)
    height = Column(Float)
    temperature = Column(Float)
    blood_sugar = Column(Float)
    cholesterol = Column(Float)
    steps = Column(Integer)
    sleep_hours = Column(Float)
    mood_level = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)

class HealthData(BaseModel):
    heart_rate: int
    blood_pressure: str
    oxygen_level: int
    weight: float
    height: float
    temperature: float
    blood_sugar: float
    cholesterol: float
    steps: int
    sleep_hours: float
    mood_level: int
    timestamp: datetime

    class Config:
        from_attributes = True


class User(BaseModel):
    id: int
    username: str
    age: int
    gender: str
    health_data: List[HealthData] = []

    class Config:
        from_attributes = True

class UserCreate(BaseModel):
    username: str
    password: str
    age: int
    gender: str

class UserLogin(BaseModel):
    username: str
    password: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = "23jm32un0urp2b9tu"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=15)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.get("/me", response_model=User)
def read_users_me(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    current_user = get_current_user(token=token, db=db)
    return current_user

@app.post("/register/", tags=["Auth"]) 
async def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(UserDB).filter(UserDB.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = hash_password(user.password)
    new_user = UserDB(username=user.username, hashed_password=hashed_password, age=user.age, gender=user.gender)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return {"message": "User registered successfully"}

@app.post("/login/", tags=["Auth"])
async def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(UserDB).filter(UserDB.username == user.username).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": db_user.username}, expires_delta=access_token_expires)
    
    return {"access_token": access_token, "token_type": "bearer"}

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except:
        raise credentials_exception

    user = db.query(UserDB).filter(UserDB.username == username).first()
    if user is None:
        raise credentials_exception

    return user

@app.get("/users/{user_id}", response_model=User, tags=["Users"])
async def get_user(user_id: int, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    db_user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found.")
    
    health_data = db.query(HealthDataDB).filter(HealthDataDB.user_id == user_id).all()
    user = User(id=db_user.id, username=db_user.username, age=db_user.age, gender=db_user.gender, 
                health_data=[HealthData(**data.__dict__) for data in health_data])
    return user

@app.post("/users/{user_id}/health", tags=["Health"])
async def add_health_data(user_id: int, data: HealthData, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    health_entry = HealthDataDB(
        user_id=user_id,
        heart_rate=data.heart_rate,
        blood_pressure=data.blood_pressure,
        oxygen_level=data.oxygen_level,
        weight=data.weight,
        height=data.height,
        temperature=data.temperature,
        blood_sugar=data.blood_sugar,
        cholesterol=data.cholesterol,
        steps=data.steps,
        sleep_hours=data.sleep_hours,
        mood_level=data.mood_level,
        timestamp=data.timestamp
    )
    db.add(health_entry)
    db.commit()
    db.refresh(health_entry)
    return {"message": "Health data added successfully"}


@app.put("/users/{user_id}/health/{timestamp}", response_model=HealthData, tags=["Health"])
async def update_health_data(user_id: int, timestamp: datetime, health_data: HealthData, db: Session = Depends(get_db)):
    db_user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found.")
    
    existing_data = db.query(HealthDataDB).filter(HealthDataDB.user_id == user_id, 
                                                  HealthDataDB.timestamp == timestamp).first()
    if not existing_data:
        raise HTTPException(status_code=404, detail="Health data not found.")
    
    for key, value in health_data.dict().items():
        setattr(existing_data, key, value)
    
    db.commit()
    db.refresh(existing_data)
    return health_data

@app.delete("/users/{user_id}/health/{timestamp}", response_model=HealthData, tags=["Health"])
async def delete_health_data(user_id: int, timestamp: datetime, db: Session = Depends(get_db)):
    db_user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found.")
    
    existing_data = db.query(HealthDataDB).filter(HealthDataDB.user_id == user_id, 
                                                  HealthDataDB.timestamp == timestamp).first()
    if not existing_data:
        raise HTTPException(status_code=404, detail="Health data not found.")
    
    db.delete(existing_data)
    db.commit()
    return HealthData(**existing_data.__dict__)

@app.get("/users/{user_id}/report", tags=["Reports"])
async def get_user_health_report(user_id: int, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    health_data = db.query(HealthDataDB).filter(HealthDataDB.user_id == user_id).all()
    if not health_data:
        raise HTTPException(status_code=404, detail="No health data found for user")

    report = {
        "count": len(health_data),
        "average_heart_rate": mean([h.heart_rate for h in health_data]),
        "average_oxygen_level": mean([h.oxygen_level for h in health_data]),
        "average_weight": mean([h.weight for h in health_data]),
        "average_height": mean([h.height for h in health_data]),
        "average_temperature": mean([h.temperature for h in health_data]),
        "average_blood_sugar": mean([h.blood_sugar for h in health_data]),
        "average_cholesterol": mean([h.cholesterol for h in health_data]),
        "average_steps": mean([h.steps for h in health_data]),
        "average_sleep_hours": mean([h.sleep_hours for h in health_data]),
        "average_mood_level": mean([h.mood_level for h in health_data]),
        "latest_blood_pressure": health_data[-1].blood_pressure,
        "last_updated": max([h.timestamp for h in health_data])
    }
    return report

@app.get("/users/{user_id}/recommendations", tags=["Recommendations"])
async def get_user_recommendations(user_id: int, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    h = db.query(HealthDataDB).filter(HealthDataDB.user_id == user_id).order_by(HealthDataDB.timestamp.desc()).first()
    if not h:
        raise HTTPException(status_code=404, detail="No health data found for user")

    recs = []

    if h.heart_rate > 100:
        recs.append("Высокий пульс. Снизьте нагрузку и проконсультируйтесь с врачом.")
    elif h.heart_rate < 60:
        recs.append("Низкий пульс. Возможна брадикардия — обратитесь к специалисту.")

    if h.oxygen_level < 95:
        recs.append("Пониженный уровень кислорода. Обеспечьте доступ свежего воздуха.")

    if "140" in h.blood_pressure or "150" in h.blood_pressure:
        recs.append("Повышенное давление. Контроль соли и стрессов.")

    if h.temperature > 37.5:
        recs.append("Повышенная температура. Возможен воспалительный процесс.")
    elif h.temperature < 36.0:
        recs.append("Сниженная температура тела. Следите за общим состоянием.")

    if h.blood_sugar > 6.0:
        recs.append("Высокий сахар. Избегайте сладкого и пройдите обследование.")
    elif h.blood_sugar < 4.0:
        recs.append("Низкий сахар. Примите углеводы.")

    if h.cholesterol > 5.2:
        recs.append("Повышен холестерин. Ограничьте жирное, ешьте больше клетчатки.")

    if h.steps < 5000:
        recs.append("Недостаточно активности. Старайтесь делать 7000–10000 шагов в день.")

    if h.sleep_hours < 6:
        recs.append("Мало сна. Рекомендуется спать минимум 7–8 часов.")
    elif h.sleep_hours > 9:
        recs.append("Чрезмерный сон. Подумайте о качестве сна и общем самочувствии.")

    if h.mood_level < 4:
        recs.append("Низкое настроение. Отдых, спорт или поддержка близких могут помочь.")

    if not recs:
        recs.append("Все параметры в норме. Отличная работа!")

    return {"recommendations": recs}

valid_metrics = {
    "heart_rate": ("Пульс", lambda d: d.heart_rate),
    "blood_pressure": ("Давление", lambda d: int(d.blood_pressure.split("/")[0])),
    "oxygen_level": ("Оксигенация", lambda d: d.oxygen_level),
    "blood_sugar": ("Сахар", lambda d: d.blood_sugar),
    "cholesterol": ("Холестерин", lambda d: d.cholesterol),
    "steps": ("Шаги", lambda d: d.steps),
    "sleep_hours": ("Сон", lambda d: d.sleep_hours),
    "mood_level": ("Настроение", lambda d: d.mood_level),
    "temperature": ("Температура", lambda d: d.temperature),
    "weight": ("Вес", lambda d: d.weight),
}

@app.get("/users/{user_id}/charts/{metric}", tags=["Charts"])
def generate_chart(user_id: int, metric: str, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    if metric not in valid_metrics:
        raise HTTPException(status_code=400, detail="Unsupported metric")

    display_name, extractor = valid_metrics[metric]
    data = db.query(HealthDataDB).filter(HealthDataDB.user_id == user_id).order_by(HealthDataDB.timestamp).all()

    if not data:
        raise HTTPException(status_code=404, detail="No any data for metric")

    x = [d.timestamp.strftime("%Y-%m-%d %H:%M") for d in data]
    y = [extractor(d) for d in data]

    plt.figure(figsize=(10, 4))
    plt.plot(x, y, marker='o', linestyle='-', color='blue')
    plt.title(f"{display_name} во времени")
    plt.xlabel("Дата")
    plt.ylabel(display_name)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.grid(True)

    buf = io.BytesIO()
    plt.savefig(buf, format="png")
    plt.close()
    buf.seek(0)

    return StreamingResponse(buf, media_type="image/png")

