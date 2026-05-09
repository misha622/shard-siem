#!/bin/bash
# Автоматическое исправление Defence Pipeline + Honeypot EventBus
# Три точечных исправления в shard_deception_technology.py

FILE="shard_deception_technology.py"
BACKUP="${FILE}.backup_$(date +%Y%m%d_%H%M%S)"

echo "📦 Создаю бэкап: $BACKUP"
cp "$FILE" "$BACKUP"

echo ""
echo "🔧 Исправление 1: добавляю event_bus в NetworkHoneypot.__init__()"
# Ищем строку "self.callback = callback" в __init__ и добавляем после неё self.event_bus = None
python3 -c "
import re

with open('$FILE', 'r') as f:
    content = f.read()

# Исправление 1: добавляем self.event_bus = None после self.callback = callback
# Ищем первое вхождение (в __init__)
old1 = '        self.callback = callback\n        self.socket = None'
new1 = '        self.callback = callback\n        self.event_bus = None  # EventBus для публикации алертов\n        self.socket = None'
content = content.replace(old1, new1, 1)
print('✅ Исправление 1: event_bus добавлен в NetworkHoneypot.__init__()')
print(f'   Замен: {content.count(new1)}')

with open('$FILE', 'w') as f:
    f.write(content)
"

echo ""
echo "🔧 Исправление 2: добавляю hp.event_bus = self.event_bus в _init_traps()"
python3 -c "
with open('$FILE', 'r') as f:
    lines = f.readlines()

# Ищем строку где создаётся NetworkHoneypot и callback=self._on_trap_triggered
# Добавляем hp.event_bus = self.event_bus после закрывающей скобки
new_lines = []
fixed = False
for i, line in enumerate(lines):
    new_lines.append(line)
    # Ищем строку с 'callback=self._on_trap_triggered)'
    if 'callback=self._on_trap_triggered)' in line and not fixed:
        # Добавляем новую строку после закрывающей скобки
        indent = ' ' * (len(line) - len(line.lstrip()))
        new_lines.append(f'{indent}hp.event_bus = self.event_bus  # Публикация алертов в EventBus\n')
        fixed = True
        print(f'✅ Исправление 2: event_bus назначен для NetworkHoneypot (строка {i+1})')

with open('$FILE', 'w') as f:
    f.writelines(new_lines)

if not fixed:
    print('❌ Исправление 2: НЕ НАЙДЕНА строка callback=self._on_trap_triggered')
"

echo ""
echo "🔧 Исправление 3: добавляю публикацию в EventBus в _handle_connection()"
python3 -c "
with open('$FILE', 'r') as f:
    content = f.read()

# Ищем alert-словарь и добавляем публикацию ДО логгера
# Ищем паттерн: создание alert + логгер
old_pattern = '''            explanation': f'Connection to honeypot {self.name} from {src_ip}'
        }

        if self.logger:'''

new_pattern = '''            explanation': f'Connection to honeypot {self.name} from {src_ip}'
        }

        # Публикуем алерт в EventBus для Defence Pipeline
        if self.event_bus:
            self.event_bus.publish('honeypot.connection', alert)
            self.event_bus.publish('alert.detected', alert)

        if self.logger:'''

count = content.count(old_pattern)
content = content.replace(old_pattern, new_pattern)
print(f'✅ Исправление 3: публикация в EventBus добавлена ({count} вхождений заменено)')

with open('$FILE', 'w') as f:
    f.write(content)
"

echo ""
echo "============================================"
echo "✅ ВСЕ ИСПРАВЛЕНИЯ ПРИМЕНЕНЫ!"
echo "============================================"
echo ""
echo "📊 Проверка:"
grep -n "event_bus.*None.*EventBus" "$FILE" | head -1
grep -n "hp.event_bus = self.event_bus" "$FILE" | head -1
grep -n "self.event_bus.publish('honeypot.connection'" "$FILE" | head -1
echo ""
echo "📦 Бэкап сохранён: $BACKUP"
echo ""
echo "🚀 Теперь перезапусти SHARD и атакуй!"
echo ""
