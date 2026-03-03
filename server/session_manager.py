import secrets
from typing import Dict, Any
from .redis_store import RedisStore

class SessionManager:
    def __init__(self, redis_store: RedisStore):
        self.redis = redis_store

    def generate_session_token(self) -> str:
        return secrets.token_hex(32)

    async def create_session(self, client_id: str, shared_secret: bytes) -> str:
        session_token = self.generate_session_token()
        session_data = {
            "client_id": client_id,
            "shared_secret": shared_secret.hex(),
            # expire time is handled by redis TTL
        }
        # default expire 1 hour (3600s)
        await self.redis.save_session(session_token, session_data, 3600)
        return session_token

    async def get_session(self, session_token: str) -> Dict[str, Any]:
        """Returns session data if valid, otherwise None"""
        return await self.redis.get_session(session_token)

    async def check_anomaly(self, client_id: str) -> bool:
        """
        Returns True if client is blocked due to too many failed attempts.
        """
        attempts = await self.redis.get_failed_attempts(client_id)
        if attempts >= 5: # Block after 5 failed attempts
            return True
        return False

    async def record_failed_attempt(self, client_id: str):
        await self.redis.increment_failed_attempts(client_id, expire_seconds=300)
