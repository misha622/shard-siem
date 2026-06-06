import sys
import os

# Добавляем корень проекта в sys.path чтобы работало: from core.base import ...
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
