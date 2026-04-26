import hashlib
import secrets
from sqlmodel import Field, Relationship, SQLModel, create_engine, Session, select
from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="templates")

app: FastAPI = FastAPI()

sqlite_url = "sqlite:///store.db"
engine = create_engine(sqlite_url, connect_args={"check_same_thread": False})


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(unique=True, index = True)
    password_hash: str
    messages: list["ChatMessage"] = Relationship(back_populates="user")
    sessions: list["UserSession"] = Relationship(back_populates="user")

class UserSession(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    token: str = Field(index=True, unique=True)
    user_id: int = Field(foreign_key="user.id")
    user: User | None = Relationship(back_populates="sessions")

class ChatMessage(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    message: str
    user_id: int = Field(foreign_key="user.id")
    user: User | None = Relationship(back_populates="messages")

class ChatMessagePublic(SQLModel):
    name : str
    message : str

class PollResponse(SQLModel):
    messages: list[ChatMessagePublic]

class SendResponse(SQLModel):
    ok: bool

class AuthRequest(SQLModel):
    name: str
    password: str

class AuthResponse(SQLModel):
    ok : bool

class ChatMessageCreate(SQLModel):
    message : str





def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

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

    # Charge explicitement le User pour éviter le lazy loading hors session
    return session.get(User, user_session.user_id)



@app.get("/chat", response_class=HTMLResponse)
async def chat(request: Request) -> HTMLResponse:
    with Session(engine) as session:
        user = get_current_user(request, session)
        if user is None:
            return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(request=request, name="chat_1.html", context={"user_name": user.name})


@app.get("/login", response_class=HTMLResponse)
async def log(request: Request) -> str:
    return templates.TemplateResponse(request=request, name="login_0.html", context={})


@app.post("/login", response_model=AuthResponse)
async def login(auth: AuthRequest, response: Response) -> AuthResponse:
    with Session(engine) as session:
        statement = select(User).where(User.name == auth.name)
        user = session.exec(statement).first()
        if user is None or user.password_hash != hash_password(auth.password):
            raise HTTPException(status_code=400, detail="Invalid name or password")

        user_session = UserSession(
            token=create_session_token(),
            user_id=user.id
        )
        session.add(user_session)
        session.commit()

        response.set_cookie(
            key="session_token",
            value=user_session.token,
            httponly=True
        )
        return AuthResponse(ok=True)


@app.get("/poll", response_model=PollResponse)
async def poll(request: Request) -> PollResponse:
    with Session(engine) as session:
        current_user = get_current_user(request, session)
        if current_user is None:
            raise HTTPException(status_code=401, detail="Not authenticated")

        statement = select(ChatMessage).order_by(ChatMessage.id)
        messages = session.exec(statement).all()
        public_messages = []
        for message in messages:
            user = session.get(User, message.user_id)
            if user is not None:
                public_messages.append(
                    ChatMessagePublic(name=user.name, message=message.message)
                )
    return PollResponse(messages=public_messages)


@app.post("/send", response_model=SendResponse)
async def send(request: Request, msg: ChatMessageCreate) -> SendResponse:
    with Session(engine) as session:
        current_user = get_current_user(request, session)
        if current_user is None:
            raise HTTPException(status_code=401, detail="Not authenticated")

        new_msg = ChatMessage(message=msg.message, user_id=current_user.id)
        session.add(new_msg)
        session.commit()
   
    return SendResponse(ok=True)


@app.post("/register", response_model=AuthResponse)
async def register(auth: AuthRequest, response: Response) -> AuthResponse:
    with Session(engine) as session:
        statement = select(User).where(User.name == auth.name)
        existing_user = session.exec(statement).first()
        if existing_user is not None:
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


@app.on_event("startup")
def on_startup():
    create_db_and_tables()