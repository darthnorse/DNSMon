# DNSMon - DNS Ad-Blocker Monitor

## System Architecture

### Overview
DNSMon is a full-stack web application for monitoring multiple Pi-hole (and soon AdGuard Home) DNS servers with real-time alerts and comprehensive querying capabilities.

### Tech Stack
- **Backend**: FastAPI (Python 3.11+)
- **Frontend**: React 18 with TypeScript
- **Database**: PostgreSQL 16 with timezone-aware timestamps
- **ORM**: SQLAlchemy (async)
- **Styling**: Tailwind CSS
- **Containerization**: Docker & Docker Compose

### Architecture Diagram
```
┌─────────────┐
│   Browser   │
└──────┬──────┘
       │ HTTP/REST
       ↓
┌─────────────┐
│  React SPA  │  (Port 8000, served by FastAPI)
│   TypeScript│
└──────┬──────┘
       │ /api/*
       ↓
┌──────────────────┐
│   FastAPI        │
│   - API routes   │
│   - Background   │
│     scheduler    │
└────┬────────┬────┘
     │        │
     │        ↓ Polls every 60s
     │   ┌──────────┐
     │   │ Pi-hole  │
     │   │ Servers  │
     │   └──────────┘
     │
     ↓ Async queries
┌──────────────┐
│  PostgreSQL  │
│  - Queries   │
│  - Settings  │
│  - Alerts    │
└──────────────┘
```

### Database-Backed Configuration
**All configuration is stored in PostgreSQL:**
- Application settings (polling intervals, Telegram config, CORS)
- Pi-hole server configurations
- Alert rules
- Settings changelog (audit trail)

**No .env or config.yml needed** (except DATABASE_URL in docker-compose.yml)

### Directory Structure
```
dnsmon/
├── backend/
│   ├── api.py           # FastAPI routes
│   ├── config.py        # Settings loader (from DB)
│   ├── database.py      # SQLAlchemy setup
│   ├── models.py        # Database models
│   ├── ingestion.py     # Pi-hole polling logic
│   ├── service.py       # Background scheduler
│   ├── alerts.py        # Alert engine
│   └── notifications.py # Telegram notifications
├── frontend/
│   ├── src/
│   │   ├── pages/       # React page components
│   │   ├── types/       # TypeScript interfaces
│   │   ├── utils/       # API client & utilities
│   │   └── App.tsx      # Main app component
│   └── build/           # Production build
├── docker-compose.yml   # Container orchestration
├── Dockerfile           # Multi-stage build
└── migrate_to_db_settings.py  # Migration script
```

---

## Coding Guidelines

### 1. DRY Principle (Don't Repeat Yourself)
**Extract common logic into reusable functions**

❌ **Bad:**
```python
# Repeating date formatting in multiple places
def get_queries(db):
    queries = await db.execute(select(Query))
    return [
        {
            'id': q.id,
            'timestamp': q.timestamp.isoformat() if q.timestamp else None,
            'domain': q.domain
        }
        for q in queries
    ]

def get_alerts(db):
    alerts = await db.execute(select(Alert))
    return [
        {
            'id': a.id,
            'timestamp': a.timestamp.isoformat() if a.timestamp else None,
            'message': a.message
        }
        for a in alerts
    ]
```

✅ **Good:**
```python
# Extract to model method
class Query(Base):
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'domain': self.domain
        }

# Use consistently
queries = [q.to_dict() for q in queries.scalars()]
```

### 2. CRUD Operations (Create, Read, Update, Delete)
**Follow consistent patterns across all endpoints**

**Pattern for all CRUD endpoints:**
```python
# CREATE
@app.post("/api/resources")
async def create_resource(data: ResourceCreate, db: AsyncSession = Depends(get_db)):
    resource = Resource(**data.model_dump())
    db.add(resource)
    await db.commit()
    await db.refresh(resource)
    return resource.to_dict()

# READ (list)
@app.get("/api/resources")
async def get_resources(db: AsyncSession = Depends(get_db)):
    stmt = select(Resource).order_by(Resource.created_at.desc())
    result = await db.execute(stmt)
    return [r.to_dict() for r in result.scalars()]

# READ (single)
@app.get("/api/resources/{id}")
async def get_resource(id: int, db: AsyncSession = Depends(get_db)):
    stmt = select(Resource).where(Resource.id == id)
    result = await db.execute(stmt)
    resource = result.scalar_one_or_none()
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")
    return resource.to_dict()

# UPDATE
@app.put("/api/resources/{id}")
async def update_resource(id: int, data: ResourceUpdate, db: AsyncSession = Depends(get_db)):
    stmt = select(Resource).where(Resource.id == id)
    result = await db.execute(stmt)
    resource = result.scalar_one_or_none()
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")

    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(resource, key, value)

    await db.commit()
    await db.refresh(resource)
    return resource.to_dict()

# DELETE
@app.delete("/api/resources/{id}")
async def delete_resource(id: int, db: AsyncSession = Depends(get_db)):
    stmt = select(Resource).where(Resource.id == id)
    result = await db.execute(stmt)
    resource = result.scalar_one_or_none()
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")

    await db.delete(resource)
    await db.commit()
    return {"message": "Resource deleted"}
```

### 3. TypeScript Strict Mode
**No `any` types - TypeScript errors are blockers**

❌ **Bad:**
```typescript
const fetchData = async (id: any): Promise<any> => {
    const response = await api.get(`/endpoint/${id}`);
    return response.data;
};
```

✅ **Good:**
```typescript
interface Resource {
    id: number;
    name: string;
    created_at: string;
}

const fetchData = async (id: number): Promise<Resource> => {
    const response = await api.get<Resource>(`/endpoint/${id}`);
    return response.data;
};
```

**For error handling:**
```typescript
try {
    await settingsApi.create(data);
} catch (err: unknown) {
    // Type guard for error objects
    const error = err as { response?: { data?: { detail?: string } } };
    setError(error.response?.data?.detail || 'Failed to save');
}
```

### 4. Field Name Consistency
**Use identical naming across frontend, API, and database**

**Example: `pihole_server` everywhere (not `piholeServer` or `pihole-server`)**

```python
# Backend model
class Query(Base):
    pihole_server = Column(String(100), nullable=False)

    def to_dict(self):
        return {'pihole_server': self.pihole_server}  # Keep snake_case in API
```

```typescript
// Frontend interface
interface Query {
    pihole_server: string;  // Match backend exactly
}

// Usage
<td>{query.pihole_server}</td>
```

**Rationale:** Python uses snake_case; JavaScript can handle it. Consistency prevents bugs.

### 5. Import Organization
**All imports at the top, grouped by source**

```python
# Backend (Python)
# 1. Standard library
import os
import json
import logging
from datetime import datetime, timezone
from typing import List, Optional

# 2. External packages
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy import select, func
from pydantic import BaseModel, Field

# 3. Internal/relative imports
from .database import get_db
from .models import Query, AlertRule
from .config import get_settings
```

```typescript
// Frontend (TypeScript)
// 1. External packages
import { useState, useEffect } from 'react';
import axios from 'axios';

// 2. Internal imports
import type { Query, AlertRule } from '../types';
import { queryApi } from '../utils/api';
```

### 6. Async/Await
**Always use async/await, never mix with callbacks or promises**

❌ **Bad:**
```typescript
function loadData() {
    queryApi.search({}).then(data => {
        setQueries(data);
    }).catch(err => {
        console.error(err);
    });
}
```

✅ **Good:**
```typescript
const loadData = async () => {
    try {
        const data = await queryApi.search({});
        setQueries(data);
    } catch (err) {
        console.error(err);
        setError('Failed to load data');
    }
};
```

### 7. Error Handling
**Always catch and handle errors gracefully**

**Backend:**
```python
try:
    result = await some_operation()
    return result
except ValueError as e:
    logger.error(f"Validation error: {e}")
    raise HTTPException(status_code=400, detail=str(e))
except Exception as e:
    logger.error(f"Unexpected error: {e}")
    raise HTTPException(status_code=500, detail="Internal server error")
```

**Frontend:**
```typescript
const [error, setError] = useState<string | null>(null);

const handleSubmit = async () => {
    try {
        setError(null);
        await api.create(formData);
        setSuccessMessage('Created successfully');
    } catch (err: unknown) {
        const error = err as { response?: { data?: { detail?: string } } };
        setError(error.response?.data?.detail || 'Operation failed');
    }
};

// Display errors
{error && (
    <div className="bg-red-50 text-red-800 px-4 py-3 rounded">
        {error}
    </div>
)}
```

### 8. Type Safety
**Use Pydantic for backend, TypeScript interfaces for frontend**

**Backend validation with Pydantic:**
```python
from pydantic import BaseModel, Field, field_validator

class PiholeServerCreate(BaseModel):
    name: str = Field(max_length=100)
    url: str
    password: str
    enabled: bool = True

    @field_validator('url')
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not (v.startswith('http://') or v.startswith('https://')):
            raise ValueError("URL must start with http:// or https://")
        return v
```

**Frontend interfaces matching backend:**
```typescript
interface PiholeServerCreate {
    name: string;
    url: string;
    password: string;
    enabled?: boolean;
}
```

---

## Development Workflow

### Local Development Setup

1. **Start services:**
   ```bash
   docker compose up -d
   ```

2. **View logs:**
   ```bash
   docker compose logs -f app
   ```

3. **Access application:**
   - Frontend: http://localhost:8000
   - API docs: http://localhost:8000/docs

4. **Database access:**
   ```bash
   docker exec -it dnsmon-postgres psql -U dnsmon -d dnsmon
   ```

### Testing Endpoints

**Using curl:**
```bash
# Get queries
curl http://localhost:8000/api/queries

# Create alert rule
curl -X POST http://localhost:8000/api/alert-rules \
  -H "Content-Type: application/json" \
  -d '{"name": "Test Rule", "domain_pattern": "google"}'

# Get settings
curl http://localhost:8000/api/settings
```

### Database Migrations

**Create new tables/columns:**
1. Modify `models.py`
2. Rebuild container: `docker compose build app`
3. Restart: `docker compose up -d app`

**Manual SQL migrations:**
```bash
docker exec dnsmon-postgres psql -U dnsmon -d dnsmon -c \
  "ALTER TABLE queries ADD COLUMN new_field VARCHAR(255);"
```

### Frontend Build Process

**Development (with hot reload):**
```bash
cd frontend
npm install
npm start  # Runs on port 3000
```

**Production build:**
```bash
cd frontend
npm run build  # Creates optimized build/ directory
```

**Rebuild container with new frontend:**
```bash
docker compose build app
docker compose up -d app
```

---

## API Conventions

### RESTful Endpoint Naming
- Use nouns, not verbs
- Use plural for collections
- Use hyphen for multi-word (e.g., `/alert-rules`, not `/alertRules`)

```
GET    /api/resources       # List all
GET    /api/resources/{id}  # Get one
POST   /api/resources       # Create
PUT    /api/resources/{id}  # Update
DELETE /api/resources/{id}  # Delete
```

### Consistent Response Formats

**Success responses:**
```json
// List
[{"id": 1, "name": "Item 1"}, {"id": 2, "name": "Item 2"}]

// Single resource
{"id": 1, "name": "Item", "created_at": "2025-01-13T10:00:00Z"}

// Operation result
{"message": "Resource created successfully", "id": 123}
```

**Error responses:**
```json
{"detail": "Resource not found"}
{"detail": "Invalid value for field 'url': must start with http://"}
```

### HTTP Status Codes
- `200 OK` - Successful GET, PUT, DELETE
- `201 Created` - Successful POST
- `400 Bad Request` - Validation error
- `404 Not Found` - Resource doesn't exist
- `500 Internal Server Error` - Unexpected error

---

## Database Patterns

### Model Structure (SQLAlchemy)

**Standard pattern for all models:**
```python
class Resource(Base):
    __tablename__ = "resources"

    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Data fields
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    enabled = Column(Boolean, default=True)

    # Timestamps (always timezone-aware!)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Indexes for common queries
    __table_args__ = (
        Index('idx_resource_name', 'name'),
    )

    # Serialization method
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'enabled': self.enabled,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
```

### Timezone Handling (CRITICAL!)
**Always use timezone-aware datetimes**

```python
# Helper function
def utcnow():
    return datetime.now(timezone.utc)

# Model definition
created_at = Column(DateTime(timezone=True), default=utcnow)

# Never use naive datetime.now()!
# ❌ created_at = Column(DateTime, default=datetime.now)  # BAD!
```

### Indexing Strategy
**Index columns used in WHERE, ORDER BY, JOIN:**

```python
# Single column index
Column(String(100), index=True)

# Composite index for common query patterns
__table_args__ = (
    Index('idx_queries_timestamp_domain', 'timestamp', 'domain'),
    Index('idx_queries_unique', 'timestamp', 'domain', 'client_ip', unique=True),
)
```

---

## Frontend Patterns

### Component Structure

```
src/
├── pages/           # Full page components (Dashboard, Search, Settings)
├── components/      # Reusable UI components (future: modals, cards, etc.)
├── types/           # TypeScript interfaces
└── utils/           # Utility functions and API client
```

### State Management with useState

**Pattern for page components:**
```typescript
function MyPage() {
    // Data state
    const [items, setItems] = useState<Item[]>([]);
    const [selectedItem, setSelectedItem] = useState<Item | null>(null);

    // UI state
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [successMessage, setSuccessMessage] = useState<string | null>(null);

    // Form state
    const [formData, setFormData] = useState<ItemCreate>({
        name: '',
        enabled: true
    });

    // Load data on mount
    useEffect(() => {
        loadItems();
    }, []);

    // Auto-dismiss success messages
    useEffect(() => {
        if (successMessage) {
            const timer = setTimeout(() => setSuccessMessage(null), 5000);
            return () => clearTimeout(timer);
        }
    }, [successMessage]);

    const loadItems = async () => {
        try {
            setLoading(true);
            const data = await api.getItems();
            setItems(data);
            setError(null);
        } catch (err) {
            setError('Failed to load items');
        } finally {
            setLoading(false);
        }
    };

    return (/* JSX */);
}
```

### Form Handling and Validation

```typescript
const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    // Client-side validation
    const errors = validateForm(formData);
    if (errors.length > 0) {
        setError(errors.join('. '));
        return;
    }

    try {
        setSaving(true);
        setError(null);

        await api.create(formData);
        await loadItems();  // Refresh list
        setFormData(initialState);  // Reset form
        setSuccessMessage('Created successfully');
    } catch (err: unknown) {
        const error = err as { response?: { data?: { detail?: string } } };
        setError(error.response?.data?.detail || 'Failed to save');
    } finally {
        setSaving(false);
    }
};
```

### Dark Mode Support

**Tailwind classes for dark mode:**
```tsx
<div className="bg-white dark:bg-gray-800 text-gray-900 dark:text-white">
    <input className="border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700" />
    <button className="bg-blue-600 hover:bg-blue-700 text-white">
        Save
    </button>
</div>
```

### API Client Organization

```typescript
// utils/api.ts
import axios from 'axios';

const api = axios.create({
    baseURL: '/api',
    headers: {'Content-Type': 'application/json'},
});

// Organized by resource
export const queryApi = {
    search: async (params: QuerySearchParams): Promise<Query[]> => {
        const response = await api.get<Query[]>('/queries', { params });
        return response.data;
    },
};

export const settingsApi = {
    get: async (): Promise<SettingsResponse> => {
        const response = await api.get<SettingsResponse>('/settings');
        return response.data;
    },
    servers: {
        getAll: async (): Promise<PiholeServer[]> => { /* ... */ },
        create: async (server: PiholeServerCreate): Promise<PiholeServer> => { /* ... */ },
    },
};
```

---

## Common Pitfalls & Solutions

### 1. Timezone Issues
❌ **Problem:** Comparing naive and aware datetimes
```python
cutoff = datetime.now() - timedelta(days=7)  # Naive!
stmt = select(Query).where(Query.timestamp >= cutoff)  # Error!
```

✅ **Solution:** Always use timezone.utc
```python
cutoff = datetime.now(timezone.utc) - timedelta(days=7)
stmt = select(Query).where(Query.timestamp >= cutoff)
```

### 2. Missing await
❌ **Problem:** Forgetting await on async functions
```python
result = some_async_function()  # Returns coroutine, not result!
```

✅ **Solution:** Always await
```python
result = await some_async_function()
```

### 3. TypeScript any type
❌ **Problem:** Using `any` to bypass type errors
```typescript
const handleError = (err: any) => {
    setError(err.message);  // Unsafe!
};
```

✅ **Solution:** Proper type guards
```typescript
const handleError = (err: unknown) => {
    const error = err as { response?: { data?: { detail?: string } } };
    setError(error.response?.data?.detail || 'Unknown error');
};
```

### 4. Database Session Leaks
❌ **Problem:** Not properly closing sessions
```python
async def get_data():
    session = async_session_maker()
    result = await session.execute(select(Query))
    return result.scalars().all()  # Session never closed!
```

✅ **Solution:** Use context manager
```python
async def get_data():
    async with async_session_maker() as session:
        result = await session.execute(select(Query))
        return result.scalars().all()
```

---

## Performance Best Practices

1. **Use indexes** on frequently queried columns
2. **Limit query results** with `.limit()` or pagination
3. **Avoid N+1 queries** - use eager loading or joins
4. **Cache settings** - reload only when modified
5. **Batch operations** - process multiple items together
6. **Use async/await** throughout for non-blocking I/O

---

## Security Considerations

1. **Credentials** stored as plain text in database (secure the database itself)
2. **SQL injection** prevented by SQLAlchemy parameterized queries
3. **XSS** prevented by React's automatic escaping
4. **CORS** configured via settings (restrict to known origins in production)
5. **No authentication** currently - add before exposing to internet

---

## References

- **FastAPI Docs**: https://fastapi.tiangolo.com/
- **SQLAlchemy Async**: https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html
- **React TypeScript**: https://react-typescript-cheatsheet.netlify.app/
- **Tailwind CSS**: https://tailwindcss.com/docs

---

**Last Updated:** 2026-01-13
**Version:** 1.0.0 (Database-backed settings)
