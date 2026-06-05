#!/bin/bash
# SHARD Backup Script

BACKUP_DIR="/var/backups/shard"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="shard_backup_${TIMESTAMP}.tar.gz"

mkdir -p "$BACKUP_DIR"

echo "📦 Creating backup: $BACKUP_FILE"

# Бэкап базы данных
if [ -f shard_siem.db ]; then
    sqlite3 shard_siem.db ".backup 'shard_siem_backup.db'"
fi

# Бэкап конфигурации и моделей
tar -czf "$BACKUP_DIR/$BACKUP_FILE" \
    config.yaml \
    shard_siem_backup.db 2>/dev/null \
    models/ \
    /var/lib/shard/ \
    /etc/shard/ \
    2>/dev/null

# Очистка временного файла
rm -f shard_siem_backup.db

# Храним только последние 7 бэкапов
cd "$BACKUP_DIR"
ls -t shard_backup_*.tar.gz | tail -n +8 | xargs -r rm

echo "✅ Backup complete: $BACKUP_DIR/$BACKUP_FILE ($(du -h $BACKUP_DIR/$BACKUP_FILE | cut -f1))"
