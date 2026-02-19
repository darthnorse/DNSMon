"""
Route modules for DNSMon API.
Each module contains an APIRouter that is included in the main app.
"""
from .auth import router as auth_router
from .users import router as users_router
from .oidc_providers import router as oidc_providers_router
from .queries import router as queries_router
from .stats import router as stats_router
from .alerts import router as alerts_router
from .settings import router as settings_router
from .sync import router as sync_router
from .domains import router as domains_router
from .blocking import router as blocking_router
from .notifications import router as notifications_router
from .api_keys import router as api_keys_router

__all__ = [
    'auth_router',
    'users_router',
    'oidc_providers_router',
    'queries_router',
    'stats_router',
    'alerts_router',
    'settings_router',
    'sync_router',
    'domains_router',
    'blocking_router',
    'notifications_router',
    'api_keys_router',
]
