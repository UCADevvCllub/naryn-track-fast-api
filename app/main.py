from fastapi import FastAPI, Depends, HTTPException, status, Body
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from sqlalchemy.exc import NoResultFound
from fastapi.middleware.cors import CORSMiddleware
import socketio
from app.socket_api import sio

from . import models, schemas, database, auth
import os

# Create tables
models.Base.metadata.create_all(bind=database.engine)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all HTTP methods
    allow_headers=["*"],  # Allows all headers
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> models.User:
    payload = auth.decode_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )
    username = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
        )
    return user


def get_current_admin(current_user: models.User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required"
        )
    return current_user


@app.on_event("startup")
def create_first_admin():
    db = next(get_db())
    if db.query(models.User).first() is None:
        admin_username = os.getenv("ADMIN_USERNAME", "admin")
        admin_password = os.getenv("ADMIN_PASSWORD", "admin123")
        new_admin = models.User(
            username=admin_username,
            password=auth.get_password_hash(admin_password),
            is_admin=True,
        )
        db.add(new_admin)
        db.commit()
        print("Created initial admin user.")


@app.post("/login")
def login(data: schemas.LoginData, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == data.username).first()
    if not user or not auth.verify_password(data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    token = auth.create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}


@app.post("/change_password")
def change_password(
    data: schemas.ChangePasswordData,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not auth.verify_password(data.old_password, current_user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Old password is incorrect"
        )
    current_user.password = auth.get_password_hash(data.new_password)
    current_user.is_password_changed = True
    db.commit()
    return {"msg": "Password changed successfully."}


@app.get("/me", response_model=schemas.UserResponse)
def read_me(current_user: models.User = Depends(get_current_user)):
    return current_user


# Admin endpoints


@app.post("/users/", response_model=schemas.UserResponse)
def create_user(
    user_data: schemas.UserCreate,
    current_admin: models.User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    if db.query(models.User).filter(models.User.username == user_data.username).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists"
        )
    new_user = models.User(
        username=user_data.username,
        car_number=user_data.car_number,
        password=auth.get_password_hash(user_data.password),
        is_admin=False,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.put("/users/{user_id}", response_model=schemas.UserResponse)
def update_user(
    user_id: int,
    user_data: schemas.UserUpdate,
    current_admin: models.User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    # Admins cannot update other admins
    if user.is_admin and user.id != current_admin.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Cannot update another admin"
        )
    if user_data.username:
        user.username = user_data.username
    if user_data.car_number is not None:
        user.car_number = user_data.car_number
    if user_data.is_admin is not None:
        user.is_admin = user_data.is_admin
    db.commit()
    db.refresh(user)
    return user


@app.get("/users/", response_model=list[schemas.UserResponse])
def list_users(
    current_admin: models.User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    users = db.query(models.User).filter(models.User.is_admin == False).all()
    return users


@app.delete("/users/{user_id}", response_model=schemas.UserResponse)
def delete_user(
    user_id: int,
    current_admin: models.User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    # Prevent deleting other admins
    if user.is_admin and user.id != current_admin.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Cannot delete another admin"
        )
    db.delete(user)
    db.commit()
    return user


@app.get("/users/{user_id}", response_model=schemas.UserResponse)
def get_user_by_id(
    user_id: int,
    current_admin: models.User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    return user


fastapi_app = app
app = socketio.ASGIApp(sio, other_asgi_app=fastapi_app)
