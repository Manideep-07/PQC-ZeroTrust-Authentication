import secrets
import time
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
            "request_count": 0,
            "created_at": time.time()
        }
        # default expire 300s (5 minutes) for Level 1 Session
        await self.redis.save_session(session_token, session_data, 300)
        return session_token

    async def get_session(self, session_token: str) -> Dict[str, Any]:
        """Returns session data if valid, otherwise None"""
        return await self.redis.get_session(session_token)

    async def update_session(self, session_token: str, session_data: dict):
        await self.redis.save_session(session_token, session_data, 300)

    async def create_client_state(self, client_id: str, shared_secret: bytes, fingerprint: str):
        data = {
            "shared_secret": shared_secret.hex(),
            "device_fingerprint": fingerprint,
            "identity_verified": False
        }
        # Client state lives longer than the 300s session token (e.g., 24 hours) for Level 2 Refresh
        await self.redis.save_session(f"client_state:{client_id}", data, 86400)

    async def get_client_state(self, client_id: str) -> Dict[str, Any]:
        return await self.redis.get_session(f"client_state:{client_id}")

    async def update_client_state(self, client_id: str, updates: dict):
        state = await self.get_client_state(client_id)
        if state:
            state.update(updates)
            await self.redis.save_session(f"client_state:{client_id}", state, 86400)

    async def check_anomaly(self, client_id: str) -> bool:
        """
        Returns True if client is blocked due to too many failed attempts.
        """
        if await self.redis.is_client_blocked(client_id):
            return True
            
        attempts = await self.redis.get_failed_attempts(client_id)
        if attempts >= 5: # Block after 5 failed attempts
            await self.redis.block_client(client_id, 120)
            return True
        return False

    async def record_failed_attempt(self, client_id: str):
        await self.redis.increment_failed_attempts(client_id)

    async def check_rate_limit(self, client_id: str) -> bool:
        return await self.redis.check_rate_limit(client_id)

    async def store_challenge(self, challenge_hex: str) -> bool:
        return await self.redis.store_challenge(challenge_hex)
