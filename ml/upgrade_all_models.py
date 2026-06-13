#!/usr/bin/env python3
"""
SHARD Model Upgrader — добавляет метрики, save/load, SHAP, онлайн-обучение
во ВСЕ 39 моделей в ml/new_models/.

Запуск: python3 ml/upgrade_all_models.py
"""

import re
from pathlib import Path

# Шаблон улучшений который добавляется в каждую модель
UPGRADE_TEMPLATE = '''
    # ============================================================
    # UPGRADED: метрики, save/load, SHAP, онлайн-обучение
    # ============================================================
    
    def evaluate(self, X_test, y_test):
        """Оценить качество модели."""
        from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
        preds, scores = self.predict(X_test)
        self.metrics = {
            'f1_score': round(f1_score(y_test, preds, zero_division=0), 4),
            'precision': round(precision_score(y_test, preds, zero_division=0), 4),
            'recall': round(recall_score(y_test, preds, zero_division=0), 4),
            'roc_auc': round(roc_auc_score(y_test, scores), 4)
        }
        return self.metrics
    
    def save(self, path=None):
        """Сохранить модель."""
        import joblib
        from pathlib import Path
        save_path = Path(path) if path else Path('models') / f'{self.__class__.__name__.lower()}.joblib'
        save_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({'model': getattr(self, 'model', self), 'metrics': getattr(self, 'metrics', {})}, save_path, compress=0)
        return True
    
    def load(self, path=None):
        """Загрузить модель."""
        import joblib
        from pathlib import Path
        load_path = Path(path) if path else Path('models') / f'{self.__class__.__name__.lower()}.joblib'
        if load_path.exists():
            data = joblib.load(load_path)
            if hasattr(self, 'model'): self.model = data.get('model')
            self.metrics = data.get('metrics', {})
            self.is_trained = True
            return True
        return False
    
    def update(self, X_new, y_new=None):
        """Онлайн-дообучение."""
        try:
            self.train(X_new, y_new) if y_new is not None else self.train(X_new)
            return True
        except:
            return False
    
    def explain(self, X, top_k=10):
        """SHAP объяснения."""
        try:
            import shap
            import numpy as np
            model = getattr(self, 'model', self)
            if hasattr(model, 'predict_proba'):
                explainer = shap.TreeExplainer(model) if hasattr(model, 'feature_importances_') else shap.KernelExplainer(lambda x: self.predict(x)[1], X[:min(50, len(X))])
                shap_values = explainer.shap_values(X[:1])
                if isinstance(shap_values, list): shap_vals = shap_values[1][0] if len(shap_values) > 1 else shap_values[0][0]
                else: shap_vals = shap_values[0]
                top_idx = np.argsort(np.abs(shap_vals))[-top_k:][::-1]
                return {'top_features': [f'f_{i}' for i in top_idx], 'shap_values': shap_vals[top_idx].tolist()}
        except:
            pass
        return {'message': 'SHAP not available for this model'}
'''

def upgrade_file(filepath):
    """Добавляет улучшения в один файл модели."""
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Пропускаем если уже улучшен
    if 'def evaluate(self, X_test, y_test):' in content:
        return False
    
    # Находим последний метод и добавляем после него
    # Ищем последний def в классе
    last_def = content.rfind('\n    def ')
    if last_def < 0:
        last_def = content.rfind('\ndef ')
    
    # Находим конец метода (следующая строка без отступа или конец файла)
    end_of_method = content.find('\n', last_def + 1)
    # Ищем где метод заканчивается (строка не с пробелом)
    lines = content[last_def:].split('\n')
    method_end = 0
    for i, line in enumerate(lines[1:], 1):
        if line.strip() and not line.startswith('    ') and not line.startswith('\t'):
            method_end = i
            break
    
    insert_pos = last_def + sum(len(l) + 1 for l in lines[:method_end]) if method_end else len(content)
    
    # Вставляем улучшения перед последней строкой (обычно logger.info)
    logger_line = content.rfind('logger.info(')
    if logger_line > 0:
        # Вставляем перед logger.info
        insert_pos = content.rfind('\n', 0, logger_line)
    
    new_content = content[:insert_pos] + UPGRADE_TEMPLATE + content[insert_pos:]
    
    with open(filepath, 'w') as f:
        f.write(new_content)
    
    return True


# Запуск
model_dir = Path('ml/new_models')
upgraded = 0
skipped = 0

for py_file in sorted(model_dir.glob('shard_*.py')):
    if py_file.name in ['shard_ensemble_voting.py']:  # Уже улучшен
        continue
    
    result = upgrade_file(py_file)
    if result:
        upgraded += 1
        print(f"  ✅ {py_file.name}")
    else:
        skipped += 1
        print(f"  ⏭️ {py_file.name} (already upgraded)")

print(f"\n✅ Upgraded: {upgraded} models")
print(f"⏭️ Skipped: {skipped} models")
