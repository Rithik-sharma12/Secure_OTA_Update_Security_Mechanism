"""SQLAlchemy async database setup."""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from server.config import get_settings

settings = get_settings()

def _create_engine():
    """Create the async engine with dialect-appropriate pool settings."""
    url = settings.database_url
    is_sqlite = url.startswith("sqlite")
    kwargs: dict = {"echo": settings.database_echo}
    if not is_sqlite:
        kwargs.update(
            pool_size=settings.database_pool_size,
            max_overflow=settings.database_max_overflow,
            pool_pre_ping=True,
            pool_recycle=3600,
        )
    return create_async_engine(url, **kwargs)


engine = _create_engine()

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async database session, ensuring cleanup on exit."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Create all database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Dispose the database engine connection pool."""
    await engine.dispose()
