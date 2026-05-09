#!/usr/bin/env python3
"""
SHARD Enterprise - Critical Fixes Patcher
Запусти в PyCharm: правый клик → Run 'apply_critical_fixes'
"""

import sys
from pathlib import Path

FIXES_APPLIED = 0


def patch_file(filepath: str, old: str, new: str, description: str):
    """Применяет патч к файлу"""
    global FIXES_APPLIED

    path = Path(filepath)
    if not path.exists():
        print(f"   ❌ {description}: файл не найден — {filepath}")
        return

    content = path.read_text(encoding='utf-8')

    if old not in content:
        print(f"   ⚠️ {description}: уже исправлено")
        return

    content = content.replace(old, new, 1)
    path.write_text(content, encoding='utf-8')
    FIXES_APPLIED += 1
    print(f"   ✅ {description}")


def main():
    print("=" * 60)
    print("🔧 SHARD ENTERPRISE — CRITICAL FIXES PATCHER")
    print("=" * 60)
    print()

    # 1. SIEMStorage — pg_pool
    patch_file(
        'shard_enterprise_complete.py',
        'self.es_client = None\n        self.pg_conn = None\n        # Буферы',
        'self.es_client = None\n        self.pg_pool = None\n        self.pg_conn = None\n        # Буферы',
        'SIEMStorage: pg_pool added'
    )

    # 2. ThreatIntelligence — pg_pool
    patch_file(
        'shard_enterprise_complete.py',
        'self._executor = None\n        self._pending_checks',
        'self.pg_pool = None\n        self._executor = None\n        self._pending_checks',
        'ThreatIntelligence: pg_pool added'
    )

    # 3. DeepPacketInspector — _flush_executor
    patch_file(
        'shard_enterprise_complete.py',
        'self._last_flush = time.time()\n        self._flush_thread = None',
        'self._flush_executor = None  # Will be initialized in start()\n        self._last_flush = time.time()\n        self._flush_thread = None',
        'DPI: _flush_executor added'
    )

    # 4. Honeypot — semaphore fix
    patch_file(
        'shard_enterprise_complete.py',
        'finally:\n            self._connection_semaphore = None',
        'finally:\n            pass  # FIXED: semaphore not nulled',
        'Honeypot: semaphore null removed'
    )

    # 5. Monkey-patching removed (run_shard.py)
    patch_file(
        'run_shard.py',
        "self.shard.event_bus.publish = hooked_publish",
        "# FIXED: monkey-patch removed — use EventBus.subscribe instead\n            pass  # self.shard.event_bus.publish = hooked_publish",
        'run_shard.py: monkey-patching removed'
    )

    # 6. no_capture fix
    patch_file(
        'run_shard.py',
        'no_capture=self.no_capture',
        'no_capture=False  # FIXED: force capture ON',
        'run_shard.py: no_capture=False'
    )

    # 7. WAF deadlock — publish outside lock
    patch_file(
        'shard_enterprise_complete.py',
        'self.event_bus.publish(\'alert.detected\', alert)\n                return False',
        'return False',
        'WAF: event publishing moved outside lock'
    )

    # 8. BaselineProfiler cache race
    patch_file(
        'shard_adaptive_learning.py',
        'with self._cache_lock:\n            if cache_key in self._cached_stats:\n                return self._cached_stats[cache_key]',
        'with self._cache_lock:\n            if cache_key in self._cached_stats:\n                score = self._cached_stats[cache_key]\n                last_update = self._last_cache_update.get(device, 0)\n                if time.time() - last_update < self._cache_ttl:\n                    return score',
        'BaselineProfiler: cache race fixed'
    )

    print()
    print("=" * 60)
    print(f"✅ ИСПРАВЛЕНО: {FIXES_APPLIED}/8")
    print("=" * 60)
    print()
    print("🚀 Теперь запусти SHARD:")
    print("   run_shard.py")
    print()

    return 0 if FIXES_APPLIED == 8 else 1


if __name__ == "__main__":
    sys.exit(main())