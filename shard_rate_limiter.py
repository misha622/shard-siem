#!/usr/bin/env python3
"""SHARD API Rate Limiter — защита от DDoS и перебора"""

import time, threading
from collections import defaultdict
from typing import Dict, Tuple

class RateLimiter:
    def __init__(self, max_requests=100, window=60, block_duration=300):
        self.max_requests = max_requests
        self.window = window
        self.block_duration = block_duration
        self.requests = defaultdict(list)
        self.blocked = {}
        self._lock = threading.Lock()
        self._cleanup_time = time.time()
    
    def is_allowed(self, ip: str) -> Tuple[bool, str]:
        with self._lock:
            now = time.time()
            
            if ip in self.blocked:
                if now < self.blocked[ip]:
                    remaining = int(self.blocked[ip] - now)
                    return False, f"Blocked for {remaining}s"
                else:
                    del self.blocked[ip]
            
            cutoff = now - self.window
            self.requests[ip] = [t for t in self.requests[ip] if t > cutoff]
            self.requests[ip].append(now)
            
            if len(self.requests[ip]) > self.max_requests:
                self.blocked[ip] = now + self.block_duration
                return False, f"Rate limit exceeded. Blocked for {self.block_duration}s"
            
            # Очистка старых IP раз в 5 минут
            if now - self._cleanup_time > 300:
                self.requests = {k: v for k, v in self.requests.items() if v}
                self._cleanup_time = now
            
            remaining = self.max_requests - len(self.requests[ip])
            return True, f"{remaining}/{self.max_requests} requests remaining"

# Глобальный экземпляр
limiter = RateLimiter(max_requests=100, window=60, block_duration=300)

def check_rate_limit(ip: str) -> Tuple[bool, str]:
    return limiter.is_allowed(ip)

def get_stats() -> Dict:
    with limiter._lock:
        return {
            'tracked_ips': len(limiter.requests),
            'blocked_ips': len(limiter.blocked),
            'max_requests': limiter.max_requests,
            'window': limiter.window,
        }
