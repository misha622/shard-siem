# DecisionFusion — Оркестратор SHARD

## Уровни защиты
1. Rule-Based — мгновенная реакция на критические атаки
2. RL Agent (DQN) — обученная модель выбора действий
3. Heuristic + Defender — генерация кода защиты
4. Smart Firewall — исполнение правил

## Действия
0: ignore, 1: log, 2: throttle, 3: block_temp (30m), 4: block_perm (24h)

## Интеграция
from modules.decision_fusion import init_decision_fusion
fusion = init_decision_fusion(event_bus, rl_defense, defender, firewall, ml_engine)
