
#!/usr/bin/env python3
"""SHARD Redis EventBus — Horizontal scaling for cluster deployment"""
import json
import time
import threading
import logging
from typing import Dict, Callable, Any
from collections import defaultdict

try:
    import redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

try:
    from kafka import KafkaProducer, KafkaConsumer
    HAS_KAFKA = True
except ImportError:
    HAS_KAFKA = False


class RedisEventBus:
    """Redis-backed EventBus для кластера SHARD"""
    
    def __init__(self, redis_url="redis://localhost:6379", 
                 channel_prefix="shard:events:"):
        self.redis_url = redis_url
        self.channel_prefix = channel_prefix
        self._running = False
        self._subscribers: Dict[str, list] = defaultdict(list)
        self._lock = threading.RLock()
        
        if HAS_REDIS:
            self.redis = redis.from_url(redis_url, decode_responses=True)
            self.pubsub = self.redis.pubsub()
            self.logger = logging.getLogger("SHARD.RedisBus")
            self.logger.info("✅ Redis EventBus initialized")
        else:
            self.redis = None
            self.pubsub = None
            self.logger = logging.getLogger("SHARD.RedisBus")
            self.logger.warning("⚠️ Redis not available, using in-process fallback")
    
    def publish(self, event_type: str, data: Any):
        """Publish event to Redis channel"""
        if self.redis and HAS_REDIS:
            channel = f"{self.channel_prefix}{event_type}"
            message = json.dumps({
                'type': event_type,
                'data': data,
                'timestamp': time.time()
            })
            self.redis.publish(channel, message)
            # Also push to list for replay/reliability
            self.redis.lpush(f"{self.channel_prefix}log", message)
            self.redis.ltrim(f"{self.channel_prefix}log", 0, 10000)
        
        # Always notify local subscribers
        with self._lock:
            for callback in self._subscribers.get(event_type, []):
                try:
                    callback(data)
                except Exception as e:
                    self.logger.error(f"Subscriber error: {e}")
    
    def subscribe(self, event_type: str, callback: Callable):
        """Subscribe to event type"""
        with self._lock:
            self._subscribers[event_type].append(callback)
        
        if self.redis and HAS_REDIS:
            channel = f"{self.channel_prefix}{event_type}"
            self.pubsub.subscribe(channel)
        
        # Return unsubscribe function
        def unsubscribe():
            with self._lock:
                if callback in self._subscribers[event_type]:
                    self._subscribers[event_type].remove(callback)
        
        return unsubscribe
    
    def start(self):
        """Start listening for Redis messages in background thread"""
        if not self.redis or not HAS_REDIS:
            return
        
        self._running = True
        
        def listener():
            while self._running:
                try:
                    message = self.pubsub.get_message(timeout=1.0)
                    if message and message['type'] == 'message':
                        data = json.loads(message['data'])
                        with self._lock:
                            for callback in self._subscribers.get(data['type'], []):
                                try:
                                    callback(data['data'])
                                except Exception:
                                    pass
                except Exception:
                    time.sleep(1)
        
        threading.Thread(target=listener, daemon=True, name="RedisBus-Listener").start()
        self.logger.info("🚀 Redis EventBus listener started")
    
    def stop(self):
        """Graceful shutdown"""
        self._running = False
        if self.pubsub:
            self.pubsub.close()
        if self.redis:
            self.redis.close()
    
    def health_check(self) -> dict:
        """Health status of the bus"""
        status = {'type': 'RedisEventBus'}
        if self.redis:
            try:
                self.redis.ping()
                status['redis'] = 'connected'
            except:
                status['redis'] = 'disconnected'
        else:
            status['redis'] = 'not_configured'
        
        with self._lock:
            status['subscribers'] = sum(len(v) for v in self._subscribers.values())
            status['event_types'] = len(self._subscribers)
        
        return status


class KafkaEventBus:
    """Kafka-backed EventBus for high-throughput clusters"""
    
    def __init__(self, bootstrap_servers="localhost:9092", 
                 topic_prefix="shard-events-"):
        self.bootstrap_servers = bootstrap_servers
        self.topic_prefix = topic_prefix
        self._running = False
        self._subscribers: Dict[str, list] = defaultdict(list)
        self._lock = threading.RLock()
        
        if HAS_KAFKA:
            self.producer = KafkaProducer(
                bootstrap_servers=bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                compression_type='gzip',
                linger_ms=10,  # Batch for throughput
                batch_size=16384
            )
            self.logger = logging.getLogger("SHARD.KafkaBus")
            self.logger.info("✅ Kafka EventBus initialized")
        else:
            self.producer = None
            self.logger = logging.getLogger("SHARD.KafkaBus")
            self.logger.warning("⚠️ Kafka not available")
    
    def publish(self, event_type: str, data: Any):
        """Publish to Kafka topic"""
        message = {
            'type': event_type,
            'data': data,
            'timestamp': time.time()
        }
        
        if self.producer:
            topic = f"{self.topic_prefix}{event_type}"
            self.producer.send(topic, message)
        
        # Local delivery
        with self._lock:
            for callback in self._subscribers.get(event_type, []):
                try:
                    callback(data)
                except Exception:
                    pass
    
    def subscribe(self, event_type: str, callback: Callable):
        """Subscribe with Kafka consumer in background"""
        with self._lock:
            self._subscribers[event_type].append(callback)
        
        if HAS_KAFKA:
            topic = f"{self.topic_prefix}{event_type}"
            consumer = KafkaConsumer(
                topic,
                bootstrap_servers=self.bootstrap_servers,
                auto_offset_reset='latest',
                value_deserializer=lambda v: json.loads(v.decode('utf-8')),
                group_id='shard-consumer-group'
            )
            
            def consumer_loop():
                for message in consumer:
                    with self._lock:
                        for cb in self._subscribers.get(event_type, []):
                            try:
                                cb(message.value['data'])
                            except Exception:
                                pass
            
            threading.Thread(target=consumer_loop, daemon=True, 
                           name=f"Kafka-{event_type}").start()
        
        def unsubscribe():
            with self._lock:
                if callback in self._subscribers[event_type]:
                    self._subscribers[event_type].remove(callback)
        
        return unsubscribe
    
    def stop(self):
        """Graceful shutdown"""
        if self.producer:
            self.producer.flush()
            self.producer.close()
