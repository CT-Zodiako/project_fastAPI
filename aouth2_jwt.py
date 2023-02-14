from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from datetime import datetime, timedelta

ALGORITHM = "HS256"
ACCESS_TOKEN_DURATION = 1
SECRET = "2b18ce702da5bc9884e757c170747800ca24f50a1f33e801770446733e8a7f7a"

app = FastAPI()

oauth2 = OAuth2PasswordBearer(tokenUrl="login")

crypt = CryptContext(schemes=["bcrypt"])


class User(BaseModel):
    username: str
    full_name: str
    email: str
    disabled: bool


class UserDB(User):
    password: str


users_db = {
    "zodiako": {
        "username": "zodiako",
        "full_name": "Cristian Tovar",
        "email": "cristian@gmail.com",
        "disabled": False,
        "password": "$2a$12$EsUQZ26DjOIf5JA4MKuPEu2DwU8czQfKw/OTufXaTPlmh6F1KjpGa"
    },
    "zodiako2": {
        "username": "zodiako2",
        "full_name": "Cristian2 Tovar2",
        "email": "cristian2@gmail.com",
        "disabled": True,
        "password": "$2a$12$f8zzR.z7Y5xg2KsAjf6YCOMV9yurNihO39IaIR3Pa400fNW9oKl/G"
    }
}


def search_user_db(username: str):
    if username in users_db:
        return UserDB(**users_db[username])

def  search_user(username: str):
    if username in users_db:
        return User(**users_db[username])

async def auth_user(token: str = Depends(oauth2)):
    exeption = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="credenciales de autorizacion invalidas",headers={"WWW-Authenticate":"Bearer"})
    try:
        username = jwt.decode(token,SECRET,algorithms=[ALGORITHM]).get("sub")
        if username is None:
            raise exeption
    except JWTError:
        raise exeption
    return search_user(username)

async def current_user( user:User = Depends(auth_user)):
    if user.disabled:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Usuario inactivo")
    return user


@app.post("/login")
async def login(form: OAuth2PasswordRequestForm = Depends()):
    user_db = users_db.get(form.username)
    if not user_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="El usuario no es correcto"
        )
    user = search_user_db(form.username)

    if not crypt.verify(form.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Contrasenna incorrecta"
        )
    access_token = {"sub":user.username,"exp":datetime.utcnow() +timedelta(minutes=ACCESS_TOKEN_DURATION)}
    return {"access_token": jwt.encode(access_token,SECRET, algorithm=ALGORITHM), "token_type": "bearer"}

@app.get("/users/me")
async def me(user: User = Depends(current_user)):
    return user


@app.get("/hola")
async def hola():
    return{"Funciona esta mierda"}