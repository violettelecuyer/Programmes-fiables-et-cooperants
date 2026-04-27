import secrets
from sqlmodel import Field, Relationship, SQLModel, create_engine, Session, select
from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import hashlib

class SendResponse(SQLModel):
    ok: bool

class AuthRequest(SQLModel):
    name: str
    password: str

class AuthResponse(SQLModel):
    ok: bool

class ChatMessageCreate(SQLModel):
    message: str

class ChatMessagePublic(SQLModel):
    name: str
    message: str

class PollResponse(SQLModel):
    messages: list[ChatMessagePublic]

class AllowUserRequest(SQLModel):
    name: str

class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(unique=True, index=True)
    password_hash: str

    messages: list["ChatMessage"] = Relationship(back_populates="user")
    sessions: list["UserSession"] = Relationship(back_populates="user")
    owned_rooms: list["ChatRoom"] = Relationship(back_populates="owner")
    room_accesses: list["RoomAccess"] = Relationship(back_populates="user")

class ChatRoom(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(unique=True, index=True)
    owner_id: int = Field(foreign_key="user.id")

    owner: User | None = Relationship(back_populates="owned_rooms")
    messages: list["ChatMessage"] = Relationship(back_populates="room")
    accesses: list["RoomAccess"] = Relationship(back_populates="room")

class RoomAccess(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    room_id: int = Field(foreign_key="chatroom.id")
    user_id: int = Field(foreign_key="user.id")

    room: ChatRoom | None = Relationship(back_populates="accesses")
    user: User | None = Relationship(back_populates="room_accesses")

class ChatMessage(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    message: str
    user_id: int = Field(foreign_key="user.id")
    room_id: int | None = Field(default=None, foreign_key="chatroom.id")

    user: User | None = Relationship(back_populates="messages")
    room: ChatRoom | None = Relationship(back_populates="messages")

class UserSession(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    token: str = Field(index=True, unique=True)
    user_id: int = Field(foreign_key="user.id")

    user: User | None = Relationship(back_populates="sessions")


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def create_session_token() -> str:
    return secrets.token_hex(32)

def get_current_user(request: Request, session: Session) -> User | None:
    token = request.cookies.get("session_token")
    if token is None:
        return None
    statement = select(UserSession).where(UserSession.token == token)
    user_session = session.exec(statement).first()
    if user_session is None:
        return None
    return session.get(User, user_session.user_id)

def get_room_by_name(room_name: str, session: Session) -> ChatRoom | None:
    statement = select(ChatRoom).where(ChatRoom.name == room_name)
    return session.exec(statement).first()

def user_can_access_room(user: User, room: ChatRoom, session: Session) -> bool:
    """Returns True if the user is the owner OR has been granted access."""
    if room.owner_id == user.id:
        return True
    statement = (
        select(RoomAccess)
        .where(RoomAccess.room_id == room.id)
        .where(RoomAccess.user_id == user.id)
    )
    return session.exec(statement).first() is not None


app: FastAPI = FastAPI()
templates = Jinja2Templates(directory="templates")

sqlite_url = "sqlite:///store.db"
engine = create_engine(sqlite_url, connect_args={"check_same_thread": False})

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

@app.on_event("startup")
def on_startup():
    create_db_and_tables()


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login_0.html", context={})

@app.post("/login", response_model=AuthResponse)
async def login(auth: AuthRequest, response: Response) -> AuthResponse:
    with Session(engine) as session:
        statement = select(User).where(User.name == auth.name)
        user = session.exec(statement).first()
        if user is None or user.password_hash != hash_password(auth.password):
            raise HTTPException(status_code=400, detail="Invalid name or password")

        user_session = UserSession(token=create_session_token(), user_id=user.id)
        session.add(user_session)
        session.commit()

        response.set_cookie(key="session_token", value=user_session.token, httponly=True)
        return AuthResponse(ok=True)


@app.post("/register", response_model=AuthResponse)
async def register(auth: AuthRequest, response: Response) -> AuthResponse:
    with Session(engine) as session:
        statement = select(User).where(User.name == auth.name)
        if session.exec(statement).first() is not None:
            raise HTTPException(status_code=400, detail="This user already exists")

        user = User(name=auth.name, password_hash=hash_password(auth.password))
        session.add(user)
        session.commit()
        session.refresh(user)

        user_session = UserSession(token=create_session_token(), user_id=user.id)
        session.add(user_session)
        session.commit()

        response.set_cookie(key="session_token", value=user_session.token, httponly=True)
        return AuthResponse(ok=True)


@app.get("/chat", response_class=HTMLResponse)
async def chat(request: Request):
    with Session(engine) as session:
        user = get_current_user(request, session)
        if user is None:
            return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(request=request, name="chat_1.html", context={"user_name": user.name})

#marche
@app.get("/poll", response_model=PollResponse)
async def poll(request: Request) -> PollResponse:
    with Session(engine) as session:
        current_user = get_current_user(request, session)
        if current_user is None:
            raise HTTPException(status_code=401, detail="Not authenticated")

        statement = select(ChatMessage).where(ChatMessage.room_id == None).order_by(ChatMessage.id)
        messages = session.exec(statement).all()
        public_messages = []
        for message in messages:
            user = session.get(User, message.user_id)
            if user is not None:
                public_messages.append(ChatMessagePublic(name=user.name, message=message.message))
    return PollResponse(messages=public_messages)

@app.post("/send", response_model=SendResponse)
async def send(request: Request, msg: ChatMessageCreate) -> SendResponse:
    with Session(engine) as session:
        current_user = get_current_user(request, session)
        if current_user is None:
            raise HTTPException(status_code=401, detail="Not authenticated")

        new_msg = ChatMessage(message=msg.message, user_id=current_user.id, room_id=None)
        session.add(new_msg)
        session.commit()
    return SendResponse(ok=True)

@app.get("/chat/{room_name}", response_class=HTMLResponse)
async def chat_room(request: Request, room_name: str):
    with Session(engine) as session:
        current_user = get_current_user(request, session)
        if current_user is None:
            return RedirectResponse(url="/login", status_code=303)

        room = get_room_by_name(room_name, session)
    
        if room is None:

            room = ChatRoom(name=room_name, owner_id=current_user.id)
            session.add(room)
            session.commit()
            session.refresh(room)
            is_owner = True
            allowed = True
        else:
            is_owner = room.owner_id == current_user.id
            allowed = user_can_access_room(current_user, room, session)
            
        return templates.TemplateResponse(
            request=request,
            name="chat_2.html",
            context={
                "user_name": current_user.name,
                "room_name": room_name,
                "is_owner": is_owner,
                "allowed": allowed,
            },
        )

@app.get("/poll/{room_name}", response_model=PollResponse)
async def poll_room(request: Request, room_name: str) -> PollResponse:
    with Session(engine) as session:
        current_user = get_current_user(request, session)
        if current_user is None:
            raise HTTPException(status_code=401, detail="Not authenticated")

        room = get_room_by_name(room_name, session)
        if room is None:
            raise HTTPException(status_code=404, detail="Room not found")

        if not user_can_access_room(current_user, room, session):
            raise HTTPException(status_code=403, detail="Not allowed in this room")

        statement = (
            select(ChatMessage)
            .where(ChatMessage.room_id == room.id)
            .order_by(ChatMessage.id)
        )
        messages = session.exec(statement).all()
        public_messages = []
        for message in messages:
            user = session.get(User, message.user_id)
            if user is not None:
                public_messages.append(ChatMessagePublic(name=user.name, message=message.message))
    return PollResponse(messages=public_messages)

@app.post("/send/{room_name}", response_model=SendResponse)
async def send_room(request: Request, room_name: str, msg: ChatMessageCreate) -> SendResponse:
    with Session(engine) as session:
        current_user = get_current_user(request, session)
        if current_user is None:
            raise HTTPException(status_code=401, detail="Not authenticated")

        room = get_room_by_name(room_name, session)
        if room is None:
            raise HTTPException(status_code=404, detail="Room not found")

        if not user_can_access_room(current_user, room, session):
            raise HTTPException(status_code=403, detail="Not allowed in this room")

        new_msg = ChatMessage(message=msg.message, user_id=current_user.id, room_id=room.id)
        session.add(new_msg)
        session.commit()
    return SendResponse(ok=True)

@app.post("/rooms/{room_name}/allow", response_model=AuthResponse)
async def allow_user(request: Request, room_name: str, body: AllowUserRequest) -> AuthResponse:
    with Session(engine) as session:
        current_user = get_current_user(request, session)
        if current_user is None:
            raise HTTPException(status_code=401, detail="Not authenticated")

        room = get_room_by_name(room_name, session)
        if room is None:
            raise HTTPException(status_code=404, detail="Room not found")

        if room.owner_id != current_user.id:
            raise HTTPException(status_code=403, detail="Only the owner can allow users")
        
        target = session.exec(select(User).where(User.name == body.name)).first()

        if target is None:
            raise HTTPException(status_code=404, detail="User not found")
        
        existing = session.exec(
            select(RoomAccess)
            .where(RoomAccess.room_id == room.id)
            .where(RoomAccess.user_id == target.id)
        ).first()
        if existing is None:
            access = RoomAccess(room_id=room.id, user_id=target.id)
            session.add(access)
            session.commit()

    return AuthResponse(ok=True)
