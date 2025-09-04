# backend/app.py
import requests
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, Text, Enum, ForeignKey, UniqueConstraint
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.sql import func
from sqlalchemy.orm import declarative_base
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Form

# Config
DATABASE_URL = "mysql+pymysql://rwessels:mgw006456@10.137.1.1/sanctumlibraria"  # Update credentials
SECRET_KEY = "your-secret-key"  # Change this (e.g., openssl rand -hex 32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

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
    author = Column(String(255))
    description = Column(Text)
    pages = Column(Integer)
    cover_url = Column(String(255))
    created_at = Column(String, server_default=func.now())

class UserBook(Base):
    __tablename__ = "user_books"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    book_id = Column(Integer, ForeignKey("books.id"))
    status = Column(Enum("to_read", "in_progress", "read", name="status_enum"), default="to_read")
    media_type = Column(Enum("physical", "electronic", "audiobook", name="media_type_enum"))
    link = Column(String(255))
    duration_minutes = Column(Integer)
    rating = Column(Integer)
    notes = Column(Text)
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
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme), db = Depends(get_db)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

# Endpoints
@app.post("/register")
async def register(username: str = Form(...), password: str = Form(...), email: str = Form(...), db = Depends(get_db)):
    hashed_password = get_password_hash(password)
    new_user = User(username=username, password_hash=hashed_password, email=email)
    try:
        db.add(new_user)
        db.commit()
        return {"msg": "User created"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Registration failed: {str(e)}")

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/search_books")
def search_books(query: str, search_type: str = "title", current_user = Depends(get_current_user)):
    if search_type == "isbn":
        url = f"https://openlibrary.org/api/books?bibkeys=ISBN:{query}&format=json&jscmd=data"
    else:
        url = f"https://openlibrary.org/search.json?{search_type}={query.replace(' ', '+')}"
    response = requests.get(url)
    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Failed to fetch from OpenLibrary")
    data = response.json()
    results = []
    if search_type == "isbn":
        key = f"ISBN:{query}"
        if key in data:
            book_data = data[key]
            results.append({
                "isbn": query,
                "title": book_data.get("title"),
                "author": ", ".join(a["name"] for a in book_data.get("authors", [])),
                "description": book_data.get("description", {}).get("value") if "description" in book_data else None,
                "pages": book_data.get("number_of_pages"),
                "cover_url": f"https://covers.openlibrary.org/b/id/{book_data['covers'][0]}-L.jpg" if "covers" in book_data else None
            })
    else:
        for doc in data.get("docs", [])[:10]:
            results.append({
                "isbn": doc.get("isbn", [None])[0],
                "title": doc.get("title"),
                "author": ", ".join(doc.get("author_name", [])),
                "description": None,
                "pages": doc.get("number_of_pages"),
                "cover_url": f"https://covers.openlibrary.org/b/id/{doc['cover_i']}-L.jpg" if "cover_i" in doc else None
            })
    return results

@app.post("/add_book")
def add_book(isbn: str, media_type: str, link: Optional[str] = None, duration_minutes: Optional[int] = None, db = Depends(get_db), current_user = Depends(get_current_user)):
    existing_book = db.query(Book).filter(Book.isbn == isbn).first()
    if not existing_book:
        url = f"https://openlibrary.org/api/books?bibkeys=ISBN:{isbn}&format=json&jscmd=data"
        response = requests.get(url).json()
        key = f"ISBN:{isbn}"
        if key not in response:
            raise HTTPException(status_code=404, detail="Book not found")
        book_data = response[key]
        new_book = Book(
            isbn=isbn,
            title=book_data.get("title"),
            author=", ".join(a["name"] for a in book_data.get("authors", [])),
            description=book_data.get("description", {}).get("value") if "description" in book_data else None,
            pages=book_data.get("number_of_pages"),
            cover_url=f"https://covers.openlibrary.org/b/id/{book_data['covers'][0]}-L.jpg" if "covers" in book_data else None
        )
        db.add(new_book)
        db.commit()
        db.refresh(new_book)
        book_id = new_book.id
    else:
        book_id = existing_book.id

    new_user_book = UserBook(
        user_id=current_user.id,
        book_id=book_id,
        media_type=media_type,
        link=link,
        duration_minutes=duration_minutes
    )
    db.add(new_user_book)
    db.commit()
    return {"msg": "Book added", "user_book_id": new_user_book.id}

@app.get("/my_library")
def my_library(title: Optional[str] = None, author: Optional[str] = None, tag: Optional[str] = None, db = Depends(get_db), current_user = Depends(get_current_user)):
    query = db.query(UserBook).filter(UserBook.user_id == current_user.id)
    if title:
        query = query.join(Book).filter(Book.title.ilike(f"%{title}%"))
    if author:
        query = query.join(Book).filter(Book.author.ilike(f"%{author}%"))
    if tag:
        query = query.join(UserBookTag).join(Tag).filter(Tag.name.ilike(f"%{tag}%"))
    results = query.all()
    return [{"id": ub.id, "title": ub.book.title, "author": ub.book.author, "status": ub.status, "media_type": ub.media_type, "cover_image": ub.book.cover_url} for ub in results]

@app.get("/book/{user_book_id}")
def get_book_details(user_book_id: int, db = Depends(get_db), current_user = Depends(get_current_user)):
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
def update_book(user_book_id: int, status: Optional[str] = None, rating: Optional[int] = None, notes: Optional[str] = None,
               progress: Optional[int] = None, tags: Optional[List[str]] = None, relationships: Optional[dict] = None,
               db = Depends(get_db), current_user = Depends(get_current_user)):
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
                db.add(UserBookRelationship(user_book_id=rel_id, related_user_book_id=user_book_id, relation=reverse_rel))
    db.commit()
    return {"msg": "Book updated"}

@app.get("/tags")
def get_tags(db = Depends(get_db)):
    return [t.name for t in db.query(Tag).all()]