import json

from fastapi import Depends
import socketio
from sqlalchemy.orm import Session
from urllib.parse import parse_qs

from . import models, schemas, database, auth

sio = socketio.AsyncServer(
    async_mode="asgi", cors_allowed_origins="*", allow_credentials=True
)

socket_app = socketio.ASGIApp(sio)

sids = {}


def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def get_current_driver(token, sid):
    db_gen = get_db()
    db = next(db_gen)
    try:
        payload = auth.decode_token(token)
        if not payload:
            await sio.emit("error", "Invalid credentials", to=sid)
            return {}, True

        username = payload.get("sub")
        if not username:
            await sio.emit("error", "Invalid token", to=sid)
            return {}, True

        user = db.query(models.User).filter(models.User.username == username).first()
        if not user:
            await sio.emit("error", "User not found", to=sid)
            return {}, True

        user_data = schemas.UserResponse.from_orm(user).dict()
    finally:
        db_gen.close()
    return user_data, False


@sio.on("disconnect")
async def discconect(sid):
    if sid in sids and sids[sid]["is_driver"]:
        await sio.emit("driver_disconnect", sid)
    if sid in sids:
        del sids[sid]


@sio.on("connect")
async def connect(sid, env):
    query_params = parse_qs(env.get("QUERY_STRING", ""))
    if "token" in query_params:
        token = query_params["token"][0]
        driver, isError = await get_current_driver(token, sid)
        if isError:
            # refuse the connection cleanly
            return False
        sids[sid] = {"is_driver": True, "user": driver}
    else:
        sids[sid] = {"is_driver": False}


@sio.on("send_location")
async def send_location(sid, msg):
    if sid in sids and sids[sid]["is_driver"]:
        driver = sids[sid]
        msg = json.loads(msg)
        msg["driver"] = driver
        msg["sid"] = sid
        await sio.emit("receive_location", json.dumps(msg))
