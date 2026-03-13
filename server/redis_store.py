import json
import redis.asyncio as redis

class RedisStore:
    def __init__(self, host="localhost", port=6379, db=0):
        self.redis_client = redis.Redis(host=host, port=port, db=db, decode_responses=True)

    async def save_session(self, session_id: str, data: dict, expire_seconds: int = 3600):
        """
        Stores key-value pair in Redis with expiration
        Data will be serialized to JSON
        """
        await self.redis_client.setex(
            f"session:{session_id}", 
            expire_seconds, 
            json.dumps(data)
        )

    async def get_session(self, session_id: str) -> dict:
        """
        Retrieve and deserialize a session from Redis.
        Returns None if not found or expired.
        """
        data = await self.redis_client.get(f"session:{session_id}")
        if data:
            return json.loads(data)
        return None

    async def delete_session(self, session_id: str):
        await self.redis_client.delete(f"session:{session_id}")
        
    async def increment_failed_attempts(self, client_id: str) -> int:
        """
        Used for basic anomaly detection tracking failed authentications
        > 5 attempts within 60 seconds -> block for 120 seconds.
        """
        key = f"failed_auth:{client_id}"
        attempts = await self.redis_client.incr(key)
        if attempts == 1:
            await self.redis_client.expire(key, 60)
        return attempts
        
    async def get_failed_attempts(self, client_id: str) -> int:
        key = f"failed_auth:{client_id}"
        attempts = await self.redis_client.get(key)
        return int(attempts) if attempts else 0

    async def block_client(self, client_id: str, block_seconds: int = 120):
        await self.redis_client.setex(f"blocked:{client_id}", block_seconds, "1")

    async def is_client_blocked(self, client_id: str) -> bool:
        return await self.redis_client.exists(f"blocked:{client_id}") > 0

    async def store_challenge(self, challenge_hex: str, expire_seconds: int = 300) -> bool:
        """
        Stores a challenge to prevent replay attacks. Returns True if successfully stored (new), False if it already exists.
        """
        # setnx returns 1 if key was set, 0 if it already existed
        is_new = await self.redis_client.setnx(f"challenge:{challenge_hex}", "1")
        if is_new:
            await self.redis_client.expire(f"challenge:{challenge_hex}", expire_seconds)
            return True
        return False

    async def check_rate_limit(self, client_id: str, limit: int = 10, window: int = 60) -> bool:
        """
        Rate limit check: max 10 requests per minute per client.
        Returns True if within limit, False if exceeded.
        """
        key = f"rate_limit:{client_id}"
        current = await self.redis_client.incr(key)
        if current == 1:
            await self.redis_client.expire(key, window)
        return current <= limit

