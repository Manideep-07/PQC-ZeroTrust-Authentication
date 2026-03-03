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
        
    async def increment_failed_attempts(self, client_id: str, expire_seconds: int = 300) -> int:
        """
        Used for basic anomaly detection tracking failed authentications
        """
        key = f"failed_auth:{client_id}"
        attempts = await self.redis_client.incr(key)
        if attempts == 1:
            await self.redis_client.expire(key, expire_seconds)
        return attempts
        
    async def get_failed_attempts(self, client_id: str) -> int:
        key = f"failed_auth:{client_id}"
        attempts = await self.redis_client.get(key)
        return int(attempts) if attempts else 0
