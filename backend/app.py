# backend/app.py
import aiohttp
import logging
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Text, Enum, ForeignKey, UniqueConstraint
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.sql import func
from sqlalchemy.orm import declarative_base
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import Form
from pydantic import BaseModel

try:
    from olclient.openlibrary import OpenLibrary
    import olclient.common as common
except ImportError as e:
    raise ImportError(
        f"Failed to import olclient: {str(e)}. Ensure 'olclient' is installed with 'pip install olclient'.")

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Config
DATABASE_URL = "mysql+pymysql://rwessels:mgw006456@10.137.1.1/sanctumlibraria"  # Update credentials
SECRET_KEY = "your-secret-key"  # Change this (e.g., openssl rand -hex 32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
DISABLE_AUTH = False  # Set to False to require authentication

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "Accept",
        "X-Requested-With",
        "*"
    ],
)

# Initialize OpenLibrary client
try:
    ol = OpenLibrary()
    logger.debug("OpenLibrary client initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize OpenLibrary client: {str(e)}")
    raise Exception(f"OpenLibrary initialization failed: {str(e)}")


# Log incoming requests for debugging
@app.middleware("http")
async def log_requests(request, call_next):
    logger.debug(f"Request: {request.method} {request.url} from {request.client.host}:{request.client.port}")
    logger.debug(f"Headers: {request.headers}")
    response = await call_next(request)
    logger.debug(f"Response status: {response.status_code}")
    return response


engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)  # Allow missing token


# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    password_hash = Column(String(255))
    email = Column(String(100), unique=True)
    created_at = Column(String, server_default=func.now())


class Book(Base):
    __tablename__ = "books"
    id = Column(Integer, primary_key=True, index=True)
    isbn = Column(String(20), unique=True)
    title = Column(String(255))
    author = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    pages = Column(Integer, nullable=True)
    cover_url = Column(String(255), nullable=True)
    created_at = Column(String, server_default=func.now())


class UserBook(Base):
    __tablename__ = "user_books"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    book_id = Column(Integer, ForeignKey("books.id"))
    status = Column(Enum("to_read", "in_progress", "read", name="status_enum"), default="to_read")
    media_type = Column(Enum("physical", "electronic", "audiobook", name="media_type_enum"))
    link = Column(String(255), nullable=True)
    duration_minutes = Column(Integer, nullable=True)
    rating = Column(Integer, nullable=True)
    notes = Column(Text, nullable=True)
    progress = Column(Integer, default=0)
    created_at = Column(String, server_default=func.now())
    __table_args__ = (UniqueConstraint('user_id', 'book_id', name='uix_user_book'),)
    user = relationship("User")
    book = relationship("Book")


class Tag(Base):
    __tablename__ = "tags"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True)


class UserBookTag(Base):
    __tablename__ = "user_book_tags"
    user_book_id = Column(Integer, ForeignKey("user_books.id"), primary_key=True)
    tag_id = Column(Integer, ForeignKey("tags.id"), primary_key=True)


class UserBookRelationship(Base):
    __tablename__ = "user_book_relationships"
    user_book_id = Column(Integer, ForeignKey("user_books.id"), primary_key=True)
    related_user_book_id = Column(Integer, ForeignKey("user_books.id"), primary_key=True)
    relation = Column(Enum("before", "same", "after", name="relation_enum"), primary_key=True)


Base.metadata.create_all(bind=engine)


# Pydantic model for /add_book
class AddBookRequest(BaseModel):
    isbn: str
    media_type: str
    link: Optional[str] = None
    duration_minutes: Optional[int] = None


# Helpers
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    logger.debug(f"Creating access token for user: {data.get('sub')}, expires at: {expire}")
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: Optional[str] = Depends(oauth2_scheme), db=Depends(get_db)):
    logger.debug(f"get_current_user called with DISABLE_AUTH={DISABLE_AUTH}, token={token}")
    if DISABLE_AUTH or token is None:
        logger.debug("Authentication disabled or no token provided, returning dummy user")
        return type('User', (), {'id': 0, 'username': 'anonymous'})()
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            logger.debug("No username in token payload")
            raise credentials_exception
    except JWTError as e:
        logger.debug(f"JWTError: {str(e)}")
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        logger.debug(f"No user found for username: {username}")
        raise credentials_exception
    logger.debug(f"User authenticated: {user.username}")
    return user


async def fetch_book_details(work_id: str) -> dict:
    """Fetch additional book details using Open Library Works API."""
    async with aiohttp.ClientSession() as session:
        url = f"https://openlibrary.org/works/{work_id}.json"
        async with session.get(url) as response:
            if response.status != 200:
                logger.warning(f"Failed to fetch work details for {work_id}: status {response.status}")
                return {}
            data = await response.json()
            description = data.get("description", {}).get("value") if isinstance(data.get("description"),
                                                                                 dict) else data.get("description")
            return {"description": description}


async def fetch_cover_url(isbn: str) -> Optional[str]:
    """Fetch Large cover image URL from Open Library Covers API."""
    async with aiohttp.ClientSession() as session:
        url = f"https://covers.openlibrary.org/b/isbn/{isbn}-L.jpg?default=false"
        async with session.get(url) as response:
            if response.status == 200:
                logger.debug(f"Cover found for ISBN {isbn}: {url}")
                return url
            elif response.status == 404:
                logger.debug(f"No cover found for ISBN {isbn}")
                return None
            elif response.status == 403:
                logger.warning(f"Rate limit exceeded for Covers API, ISBN: {isbn}")
                return None
            else:
                logger.warning(f"Unexpected response from Covers API for ISBN {isbn}: status {response.status}")
                return None


async def get_book_data(isbn: str) -> Optional[dict]:
    """Fetch book data from Open Library, with HTTP API fallback."""
    logger.debug(f"Attempting to fetch book data for ISBN: {isbn}")
    try:
        edition = ol.Edition.get(isbn=isbn)
        if edition:
            logger.debug(f"Book found via ol.Edition.get: {edition.title}")
            authors = [a.name for a in edition.authors] if edition.authors else []
            return {
                "title": edition.title or "Unknown Title",
                "authors": authors,
                "description": edition.description,
                "pages": getattr(edition, "number_of_pages", None)
            }
    except Exception as e:
        logger.warning(f"ol.Edition.get failed for ISBN {isbn}: {str(e)}")

    # Fallback to HTTP API
    logger.debug(f"Falling back to Open Library HTTP API for ISBN: {isbn}")
    async with aiohttp.ClientSession() as session:
        url = f"https://openlibrary.org/api/books?bibkeys=ISBN:{isbn}&format=json&jscmd=data"
        async with session.get(url) as response:
            logger.debug(f"HTTP API response status for ISBN {isbn}: {response.status}")
            if response.status == 200:
                data = await response.json()
                logger.debug(f"HTTP API raw response: {data}")
                book_data = data.get(f"ISBN:{isbn}", {})
                if book_data:
                    authors = [a["name"] for a in book_data.get("authors", [])] or ["Unknown Author"]
                    description = book_data.get("notes", {}).get("value") or book_data.get("description") or None
                    pages = book_data.get("number_of_pages")
                    logger.debug(
                        f"Parsed book data: title={book_data.get('title')}, authors={authors}, pages={pages}, description={description}")
                    return {
                        "title": book_data.get("title", "Unknown Title"),
                        "authors": authors,
                        "description": description,
                        "pages": pages
                    }
                else:
                    logger.error(f"No book data found in HTTP API response for ISBN {isbn}")
            else:
                logger.error(f"HTTP API request failed for ISBN {isbn}: status {response.status}")
    return None


# Endpoints
@app.post("/register")
async def register(username: str = Form(...), password: str = Form(...), email: str = Form(...), db=Depends(get_db)):
    hashed_password = get_password_hash(password)
    new_user = User(username=username, password_hash=hashed_password, email=email)
    try:
        db.add(new_user)
        db.commit()
        logger.debug(f"User registered: {username}")
        return {"msg": "User created"}
    except Exception as e:
        db.rollback()
        logger.error(f"Registration failed for {username}: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Registration failed: {str(e)}")


@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db=Depends(get_db)):
    if DISABLE_AUTH:
        logger.debug("Authentication disabled, returning dummy token")
        return {"access_token": "dummy-token", "token_type": "bearer"}
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        logger.debug(f"Login failed for username: {form_data.username}")
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    logger.debug(f"Login successful for {user.username}, token issued")
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/search_books")
async def search_books(query: str, search_type: str = "title", debug: bool = False,
                       current_user=Depends(get_current_user)):
    logger.debug(
        f"search_books called with query={query}, search_type={search_type}, debug={debug}, user={current_user.username}")
    try:
        if search_type == "isbn":
            try:
                book_data = await get_book_data(query)
                if not book_data:
                    logger.error(f"No book found for ISBN: {query}")
                    raise HTTPException(status_code=404, detail="Book not found in OpenLibrary")
                description = book_data.get("description")
                pages = book_data.get("pages")
                cover_url = await fetch_cover_url(query)
                results = [{
                    "isbn": query,
                    "title": book_data["title"],
                    "author": ", ".join(book_data["authors"]) if book_data["authors"] else None,
                    "description": description,
                    "pages": pages,
                    "cover_url": cover_url
                }]
                if debug:
                    return {"debug": book_data}
                return results
            except Exception as e:
                logger.error(f"Error fetching book from OpenLibrary: {str(e)}")
                raise HTTPException(status_code=500, detail=f"Failed to fetch book from OpenLibrary: {str(e)}")
        else:
            async with aiohttp.ClientSession() as session:
                url = f"https://openlibrary.org/search.json?{search_type}={query.replace(' ', '+')}"
                async with session.get(url) as response:
                    if response.status != 200:
                        logger.error(f"Failed to fetch from OpenLibrary: status {response.status}")
                        raise HTTPException(status_code=500, detail="Failed to fetch from OpenLibrary")
                    data = await response.json()
                    if debug:
                        return {"debug": data}
                    results = []
                    for doc in data.get("docs", [])[:10]:
                        description = doc.get("first_sentence", [None])[0] or None
                        if not description and doc.get("key"):
                            work_id = doc["key"].split("/")[-1]
                            extra_data = await fetch_book_details(work_id)
                            description = extra_data.get("description")
                        isbn = doc.get("isbn", [None])[0]
                        cover_url = await fetch_cover_url(isbn) if isbn else None
                        results.append({
                            "isbn": isbn,
                            "title": doc.get("title"),
                            "author": ", ".join(doc.get("author_name", [])) if doc.get("author_name") else None,
                            "description": description,
                            "pages": doc.get("number_of_pages"),
                            "cover_url": cover_url
                        })
                    return results
    except Exception as e:
        logger.error(f"Error in search_books: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch from OpenLibrary: {str(e)}")


@app.post("/add_book")
async def add_book(request: AddBookRequest, db=Depends(get_db), current_user=Depends(get_current_user)):
    logger.debug(
        f"add_book called with isbn={request.isbn}, media_type={request.media_type}, link={request.link}, duration_minutes={request.duration_minutes}, user={current_user.username}")

    # Validate media_type
    valid_media_types = ["physical", "electronic", "audiobook"]
    if request.media_type not in valid_media_types:
        logger.error(f"Invalid media_type: {request.media_type}")
        raise HTTPException(status_code=422, detail=f"Invalid media_type: must be one of {valid_media_types}")

    # Validate ISBN format (basic check for non-empty string)
    if not request.isbn or not request.isbn.strip():
        logger.error("ISBN is empty or invalid")
        raise HTTPException(status_code=422, detail="ISBN cannot be empty")

    # Check for existing book in database
    existing_book = db.query(Book).filter(Book.isbn == request.isbn).first()
    if not existing_book:
        try:
            logger.debug(f"Fetching book data from OpenLibrary for ISBN: {request.isbn}")
            book_data = await get_book_data(request.isbn)
            if not book_data:
                logger.error(f"No book found in OpenLibrary for ISBN: {request.isbn}")
                raise HTTPException(status_code=404, detail="Book not found in OpenLibrary")
            logger.debug(f"Book found: {book_data['title']}")
            description = book_data.get("description")
            pages = book_data.get("pages")
            authors = book_data.get("authors")
            author_str = ", ".join(authors) if authors else None
            if not authors:
                logger.warning(f"No authors found for ISBN {request.isbn}, setting author to None")
            cover_url = await fetch_cover_url(request.isbn)
            new_book = Book(
                isbn=request.isbn,
                title=book_data["title"],
                author=author_str,
                description=description,
                pages=pages,
                cover_url=cover_url
            )
            try:
                db.add(new_book)
                db.commit()
                db.refresh(new_book)
                book_id = new_book.id
                logger.debug(f"Book added to database: id={book_id}, isbn={request.isbn}")
            except Exception as e:
                db.rollback()
                logger.error(f"Database error adding book: {str(e)}")
                raise HTTPException(status_code=500, detail=f"Failed to add book to database: {str(e)}")
        except Exception as e:
            logger.error(f"Error fetching book data: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Failed to fetch book data: {str(e)}")
    else:
        book_id = existing_book.id
        logger.debug(f"Book already exists: id={book_id}, isbn={request.isbn}")

    # Check for existing user_book entry to avoid duplicates
    existing_user_book = db.query(UserBook).filter(UserBook.user_id == current_user.id,
                                                   UserBook.book_id == book_id).first()
    if existing_user_book:
        logger.error(f"Book with ISBN {request.isbn} already in user's library")
        raise HTTPException(status_code=422, detail="Book already in your library")

    # Use a default user_id for unauthenticated users if DISABLE_AUTH is True
    user_id = current_user.id if not DISABLE_AUTH else 0
    new_user_book = UserBook(
        user_id=user_id,
        book_id=book_id,
        media_type=request.media_type,
        link=request.link,
        duration_minutes=request.duration_minutes
    )
    try:
        db.add(new_user_book)
        db.commit()
        db.refresh(new_user_book)
        logger.debug(f"Book added successfully, user_book_id={new_user_book.id}")
    except Exception as e:
        db.rollback()
        logger.error(f"Database error adding user book: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to add book to user library: {str(e)}")
    return {"msg": "Book added", "user_book_id": new_user_book.id}


@app.get("/my_library")
def my_library(title: Optional[str] = None, author: Optional[str] = None, tag: Optional[str] = None, db=Depends(get_db),
               current_user=Depends(get_current_user)):
    logger.debug(f"my_library called with title={title}, author={author}, tag={tag}, user={current_user.username}")
    query = db.query(UserBook).filter(UserBook.user_id == current_user.id)
    if title:
        query = query.join(Book).filter(Book.title.ilike(f"%{title}%"))
    if author:
        query = query.join(Book).filter(Book.author.ilike(f"%{author}%"))
    if tag:
        query = query.join(UserBookTag).join(Tag).filter(Tag.name.ilike(f"%{tag}%"))
    results = query.all()
    return [{"id": ub.id, "title": ub.book.title, "author": ub.book.author, "status": ub.status,
             "media_type": ub.media_type, "cover_image": ub.book.cover_url} for ub in results]


@app.get("/book/{user_book_id}")
def get_book_details(user_book_id: int, db=Depends(get_db), current_user=Depends(get_current_user)):
    logger.debug(f"get_book_details called with user_book_id={user_book_id}, user={current_user.username}")
    ub = db.query(UserBook).filter(UserBook.id == user_book_id, UserBook.user_id == current_user.id).first()
    if not ub:
        raise HTTPException(status_code=404, detail="Book not found")
    total_pages = ub.duration_minutes / 2 if ub.media_type == "audiobook" and ub.duration_minutes else ub.book.pages
    relationships = db.query(UserBookRelationship).filter(UserBookRelationship.user_book_id == user_book_id).all()
    before = [r.related_user_book_id for r in relationships if r.relation == "before"]
    same = [r.related_user_book_id for r in relationships if r.relation == "same"]
    after = [r.related_user_book_id for r in relationships if r.relation == "after"]
    tags = [t.tag.name for t in db.query(UserBookTag).filter(UserBookTag.user_book_id == user_book_id).join(Tag).all()]
    return {
        "title": ub.book.title,
        "author": ub.book.author,
        "pages": total_pages,
        "cover_image": ub.book.cover_url,
        "status": ub.status,
        "media_type": ub.media_type,
        "link": ub.link,
        "tags": tags,
        "rating": ub.rating,
        "notes": ub.notes,
        "progress": ub.progress,
        "relationships": {"before": before, "same": same, "after": after}
    }


@app.put("/book/{user_book_id}")
def update_book(user_book_id: int, status: Optional[str] = None, rating: Optional[int] = None,
                notes: Optional[str] = None,
                progress: Optional[int] = None, tags: Optional[List[str]] = None, relationships: Optional[dict] = None,
                db=Depends(get_db), current_user=Depends(get_current_user)):
    logger.debug(f"update_book called with user_book_id={user_book_id}, user={current_user.username}")
    ub = db.query(UserBook).filter(UserBook.id == user_book_id, UserBook.user_id == current_user.id).first()
    if not ub:
        raise HTTPException(status_code=404, detail="Book not found")
    if status:
        ub.status = status
    if rating:
        ub.rating = rating
    if notes:
        ub.notes = notes
    if progress:
        if ub.media_type == "audiobook" and ub.duration_minutes:
            ub.progress = progress / 2
        else:
            ub.progress = progress
    if tags:
        db.query(UserBookTag).filter(UserBookTag.user_book_id == user_book_id).delete()
        for tag_name in tags:
            tag = db.query(Tag).filter(Tag.name == tag_name).first()
            if not tag:
                tag = Tag(name=tag_name)
                db.add(tag)
                db.commit()
                db.refresh(tag)
            db.add(UserBookTag(user_book_id=user_book_id, tag_id=tag.id))
    if relationships:
        db.query(UserBookRelationship).filter(UserBookRelationship.user_book_id == user_book_id).delete()
        for rel_type, rel_ids in relationships.items():
            for rel_id in rel_ids:
                db.add(UserBookRelationship(user_book_id=user_book_id, related_user_book_id=rel_id, relation=rel_type))
                reverse_rel = "after" if rel_type == "before" else "before" if rel_type == "after" else "same"
                db.add(
                    UserBookRelationship(user_book_id=rel_id, related_user_book_id=user_book_id, relation=reverse_rel))
    db.commit()
    return {"msg": "Book updated"}


@app.get("/tags")
def get_tags(db=Depends(get_db)):
    logger.debug("get_tags called")
    return [t.name for t in db.query(Tag).all()]