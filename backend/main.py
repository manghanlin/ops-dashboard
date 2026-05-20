"""
營運數據儀表板 — FastAPI 後端
目前使用 mock_data；串接真實資料來源時，只需替換 get_kpi_data() 內容
"""
import os
import json
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from dotenv import load_dotenv

from mock_data import MOCK

# ── 載入環境變數 ──────────────────────────────────────────
load_dotenv()

SECRET_KEY    = os.getenv("JWT_SECRET", "change-me-in-production")
ALGORITHM     = "HS256"
ACCESS_EXPIRE = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))

# 帳號清單（之後可換成 DB 或 LDAP 查詢）
USERS_DB = {
    os.getenv("ADMIN_USER", "admin"): {
        "username": os.getenv("ADMIN_USER", "admin"),
        "hashed_password": os.getenv("ADMIN_HASHED_PW", ""),
        "role": "admin",
    }
}

# ── FastAPI App ───────────────────────────────────────────
app = FastAPI(title="營運儀表板 API", version="1.0.0", docs_url="/docs")

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── 認證工具 ──────────────────────────────────────────────
pwd_ctx    = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2     = OAuth2PasswordBearer(tokenUrl="/auth/token")

class Token(BaseModel):
    access_token: str
    token_type: str

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)

def create_access_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_EXPIRE)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2)):
    exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token 無效或已過期",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload  = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None or username not in USERS_DB:
            raise exc
    except JWTError:
        raise exc
    return USERS_DB[username]

# ── Auth 端點 ─────────────────────────────────────────────
@app.post("/auth/token", response_model=Token, tags=["Auth"])
def login(form: OAuth2PasswordRequestForm = Depends()):
    user = USERS_DB.get(form.username)
    if not user or not verify_password(form.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="帳號或密碼錯誤")
    token = create_access_token({"sub": user["username"], "role": user["role"]})
    return {"access_token": token, "token_type": "bearer"}

# ── KPI 端點 ──────────────────────────────────────────────
@app.get("/api/v1/kpi", tags=["KPI"])
def get_kpi(
    period: Literal["today", "week", "month"] = "week",
    _user = Depends(get_current_user),
):
    """
    回傳指定時間段的 KPI 資料。
    結構與前端 DATA 物件完全對齊，串接真實資料來源時只改此函式。
    """
    return get_kpi_data(period)


def get_kpi_data(period: str) -> dict:
    """
    資料來源切換點：
    - 現在：回傳 MOCK 假資料
    - 未來：依 period 查詢 DB / ETL 輸出，組出相同 dict 結構後回傳
    """
    # TODO: 盤點完成後，在這裡替換成真實查詢
    # example:
    #   traffic  = query_traffic_db(period)
    #   members  = query_member_db(period)
    #   orders   = query_order_db(period)
    #   return build_response(traffic, members, orders, ...)
    return MOCK[period]


# ── 健康檢查 ──────────────────────────────────────────────
@app.get("/health", tags=["System"])
def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}
