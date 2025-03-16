from fastapi import FastAPI, Depends, HTTPException, status, Body
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, relationship, Session
from sqlalchemy.ext.declarative import declarative_base
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import List

# Инициализация базы данных и других компонентов
DATABASE_URL = "postgresql://user:password@db-1:5432/health_monitor_db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Модели SQLAlchemy
class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

class HealthData(Base):
    __tablename__ = 'health_data'

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    heart_rate = Column(Integer)
    blood_pressure = Column(String)
    blood_sugar = Column(Float)
    weight = Column(Float)
    oxygen_level = Column(Float)
    body_temperature = Column(Float)
    stress_level = Column(Integer)
    steps = Column(Integer)
    calories_burned = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="health_data")

User.health_data = relationship("HealthData", back_populates="user")

# Модели Pydantic для валидации данных
class UserCreate(BaseModel):
    name: str
    email: str
    password: str

class UserOut(BaseModel):
    id: int
    name: str
    email: str
    created_at: datetime

    class Config:
        orm_mode = True

class HealthDataCreate(BaseModel):
    heart_rate: int
    blood_pressure: str
    blood_sugar: float
    weight: float
    oxygen_level: float
    body_temperature: float
    stress_level: int
    steps: int
    calories_burned: float

class HealthDataOut(HealthDataCreate):
    id: int
    user_id: int
    timestamp: datetime

    class Config:
        orm_mode = True

class HealthReportOut(BaseModel):
    average_heart_rate: float
    average_blood_sugar: float
    average_weight: float
    average_oxygen_level: float
    average_body_temperature: float
    average_stress_level: int
    average_steps: int
    average_calories_burned: float
    recommendations: List[str]

# Инициализация приложения FastAPI
app = FastAPI()

# Безопасность и JWT
SECRET_KEY = "my_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 1 день

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Функции для работы с паролями
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# Функции для работы с JWT
def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return user_id

# Зависимости для работы с БД
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Роуты API

@app.get("/")
def read_root():
    return {"message": "API is running"}

@app.post("/register", response_model=UserOut)
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    db_user = User(name=user.name, email=user.email, password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/login")
def login(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token(data={"user_id": db_user.id})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/{user_id}", response_model=UserOut)
def get_user(user_id: int, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

@app.post("/health", response_model=HealthDataOut)
def add_health_data(health_data: HealthDataCreate, db: Session = Depends(get_db), user_id: int = Depends(get_current_user)):
    db_health_data = HealthData(user_id=user_id, **health_data.dict())
    db.add(db_health_data)
    db.commit()
    db.refresh(db_health_data)
    return db_health_data

@app.get("/health/{user_id}", response_model=List[HealthDataOut])
def get_health_data(user_id: int, db: Session = Depends(get_db)):
    db_health_data = db.query(HealthData).filter(HealthData.user_id == user_id).all()
    return db_health_data

@app.get("/health/report/{user_id}", response_model=HealthReportOut)
def generate_health_report(user_id: int, db: Session = Depends(get_db)):
    # Получаем данные за последние 7 дней
    health_data = db.query(HealthData).filter(
        HealthData.user_id == user_id,
        HealthData.timestamp >= datetime.utcnow() - timedelta(days=7)
    ).all()

    if not health_data:
        raise HTTPException(status_code=404, detail="No health data found")

    # Рассчитываем средние значения
    total_heart_rate = sum([data.heart_rate for data in health_data])
    total_blood_sugar = sum([data.blood_sugar for data in health_data])
    total_weight = sum([data.weight for data in health_data])
    total_oxygen_level = sum([data.oxygen_level for data in health_data])
    total_body_temperature = sum([data.body_temperature for data in health_data])
    total_stress_level = sum([data.stress_level for data in health_data])
    total_steps = sum([data.steps for data in health_data])
    total_calories_burned = sum([data.calories_burned for data in health_data])
    count = len(health_data)

    average_heart_rate = total_heart_rate / count
    average_blood_sugar = total_blood_sugar / count
    average_weight = total_weight / count
    average_oxygen_level = total_oxygen_level / count
    average_body_temperature = total_body_temperature / count
    average_stress_level = total_stress_level / count
    average_steps = total_steps / count
    average_calories_burned = total_calories_burned / count

    recommendations = generate_recommendations(
        average_heart_rate,
        average_blood_sugar,
        average_weight,
        average_oxygen_level,
        average_body_temperature,
        average_stress_level,
        average_steps,
        average_calories_burned
    )

    return HealthReportOut(
        average_heart_rate=average_heart_rate,
        average_blood_sugar=average_blood_sugar,
        average_weight=average_weight,
        average_oxygen_level=average_oxygen_level,
        average_body_temperature=average_body_temperature,
        average_stress_level=average_stress_level,
        average_steps=average_steps,
        average_calories_burned=average_calories_burned,
        recommendations=recommendations
    )

# Генерация рекомендаций
def generate_recommendations(heart_rate, blood_sugar, weight, oxygen_level, body_temperature, stress_level, steps, calories_burned):
    recommendations = []

    if heart_rate > 80:
        recommendations.append("Ваш пульс выше нормы. Рекомендуется снизить физическую нагрузку.")
    else:
        recommendations.append("Ваш пульс в норме.")
    
    if blood_sugar > 6.0:
        recommendations.append("Уровень сахара в крови выше нормы. Рекомендуется снизить потребление сахара.")
    else:
        recommendations.append("Уровень сахара в крови в норме.")

    if weight > 90:
        recommendations.append("Ваш вес выше нормы. Рекомендуется следить за питанием.")
    else:
        recommendations.append("Ваш вес в норме.")
    
    if oxygen_level < 95:
        recommendations.append("Уровень кислорода в крови ниже нормы. Рекомендуется проконсультироваться с врачом.")
    else:
        recommendations.append("Уровень кислорода в крови в норме.")
    
    if body_temperature > 37.5:
        recommendations.append("Температура тела выше нормы. Рекомендуется отдохнуть и проконсультироваться с врачом.")
    else:
        recommendations.append("Температура тела в норме.")
    
    if stress_level > 50:
        recommendations.append("Уровень стресса выше нормы. Рекомендуется заняться медитацией или йогой.")
    else:
        recommendations.append("Уровень стресса в норме.")

    if steps < 5000:
        recommendations.append("Вы проходите меньше 5000 шагов в день. Рекомендуется увеличить физическую активность.")
    else:
        recommendations.append("Вы проходите достаточно шагов в день.")

    if calories_burned < 2000:
        recommendations.append("Вы сжигаете недостаточно калорий. Рекомендуется увеличить физическую активность.")
    else:
        recommendations.append("Вы сжигаете достаточно калорий. Отличная работа!")

    return recommendations

@app.on_event("startup")
def startup():
    Base.metadata.create_all(engine)

# Запуск приложения
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
