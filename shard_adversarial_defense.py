
#!/usr/bin/env python3
"""SHARD Adversarial ML Defense — защита от атак на ML-модели"""
import numpy as np
import logging
from typing import List, Tuple, Optional
from dataclasses import dataclass
from collections import deque

logger = logging.getLogger("SHARD.Adversarial")

@dataclass
class AdversarialDetection:
    """Result of adversarial detection"""
    is_adversarial: bool
    attack_type: str
    confidence: float
    original_prediction: any
    cleaned_prediction: any


class AdversarialDefender:
    """Defense against adversarial ML attacks"""
    
    def __init__(self):
        self.attack_history: deque = deque(maxlen=1000)
        self.detection_threshold = 0.85
        
        # Feature squeezing parameters
        self.squeeze_bit_depth = 4  # Reduce to 4-bit color depth equivalent
        
        # Spatial smoothing
        self.smooth_window = 3
        
        logger.info("✅ Adversarial ML Defender initialized")
    
    def defend(self, features: np.ndarray, model_predict) -> AdversarialDetection:
        """Defend against adversarial examples"""
        
        # 1. Feature squeezing
        squeezed_features = self._feature_squeezing(features)
        squeezed_pred = model_predict(squeezed_features)
        
        # 2. Spatial smoothing
        smoothed_features = self._spatial_smoothing(features)
        smoothed_pred = model_predict(smoothed_features)
        
        # 3. Prediction consistency check
        original_pred = model_predict(features)
        
        # Compare predictions
        disagreement = self._calculate_disagreement(
            [original_pred, squeezed_pred, smoothed_pred]
        )
        
        is_adversarial = disagreement > 0.3
        
        if is_adversarial:
            logger.warning(f"🚨 Adversarial attack detected! Disagreement: {disagreement:.3f}")
            
            # Use majority vote of cleaned predictions
            cleaned_pred = self._majority_vote([squeezed_pred, smoothed_pred])
            
            detection = AdversarialDetection(
                is_adversarial=True,
                attack_type=self._identify_attack_type(features, squeezed_features),
                confidence=disagreement,
                original_prediction=original_pred,
                cleaned_prediction=cleaned_pred
            )
            
            self.attack_history.append(detection)
            return detection
        
        return AdversarialDetection(
            is_adversarial=False,
            attack_type='none',
            confidence=0.0,
            original_prediction=original_pred,
            cleaned_prediction=original_pred
        )
    
    def _feature_squeezing(self, features: np.ndarray) -> np.ndarray:
        """Reduce feature precision to detect adversarial perturbations"""
        # Simulate bit depth reduction
        max_val = np.max(np.abs(features))
        if max_val > 0:
            levels = 2 ** self.squeeze_bit_depth
            squeezed = np.round(features / max_val * levels) * max_val / levels
        else:
            squeezed = features.copy()
        return squeezed
    
    def _spatial_smoothing(self, features: np.ndarray) -> np.ndarray:
        """Apply spatial smoothing to remove adversarial noise"""
        if len(features.shape) == 1:
            # 1D features — apply median filter
            window = min(self.smooth_window, len(features))
            smoothed = np.convolve(
                features, 
                np.ones(window)/window, 
                mode='same'
            )
        else:
            # 2D features — apply Gaussian blur equivalent
            from scipy.ndimage import uniform_filter
            smoothed = uniform_filter(features, size=self.smooth_window)
        
        return smoothed
    
    def _calculate_disagreement(self, predictions: List) -> float:
        """Calculate disagreement between multiple predictions"""
        # Convert to numpy for vectorized comparison
        preds = [np.array(p) if not isinstance(p, (int, float)) else np.array([p]) 
                for p in predictions]
        
        # Normalize
        preds = [(p - np.min(p)) / (np.max(p) - np.min(p) + 1e-8) for p in preds]
        
        # Pairwise L2 distances
        distances = []
        for i in range(len(preds)):
            for j in range(i+1, len(preds)):
                dist = np.linalg.norm(preds[i] - preds[j])
                distances.append(dist)
        
        return np.mean(distances) if distances else 0.0
    
    def _majority_vote(self, predictions: List) -> any:
        """Majority vote among cleaned predictions"""
        if not predictions:
            return None
        
        # For classification: return most common class
        if hasattr(predictions[0], 'argmax'):
            classes = [p.argmax() for p in predictions]
            from collections import Counter
            return Counter(classes).most_common(1)[0][0]
        
        # For regression: return median
        return np.median(predictions, axis=0)
    
    def _identify_attack_type(self, original: np.ndarray, squeezed: np.ndarray) -> str:
        """Identify type of adversarial attack"""
        diff = np.abs(original - squeezed)
        mean_diff = np.mean(diff)
        max_diff = np.max(diff)
        
        if max_diff > 1.0:
            return 'FGSM'  # Fast Gradient Sign Method — large perturbations
        elif mean_diff > 0.1:
            return 'PGD'  # Projected Gradient Descent — moderate perturbations
        elif np.std(diff) > 0.5:
            return 'CW'  # Carlini-Wagner — subtle perturbations
        else:
            return 'unknown'
    
    def get_defense_statistics(self) -> dict:
        """Get statistics on detected attacks"""
        if not self.attack_history:
            return {'total_attacks': 0}
        
        attacks = list(self.attack_history)
        attack_types = {}
        
        for attack in attacks:
            attack_types[attack.attack_type] = attack_types.get(attack.attack_type, 0) + 1
        
        return {
            'total_attacks': len(attacks),
            'attack_types': attack_types,
            'avg_confidence': np.mean([a.confidence for a in attacks]),
            'last_attack_time': attacks[-1].__dict__.get('timestamp', 'unknown')
        }


class AdversarialTraining:
    """Train models to be robust against adversarial attacks"""
    
    def __init__(self, epsilon: float = 0.1, alpha: float = 0.01):
        self.epsilon = epsilon  # Maximum perturbation
        self.alpha = alpha      # Step size
    
    def generate_adversarial_example(self, model, x: np.ndarray, y: np.ndarray) -> np.ndarray:
        """Generate adversarial example using PGD attack"""
        import torch
        
        x_adv = x.clone().detach().requires_grad_(True)
        
        for _ in range(10):  # PGD iterations
            loss = torch.nn.functional.cross_entropy(model(x_adv), y)
            loss.backward()
            
            # FGSM step
            with torch.no_grad():
                x_adv = x_adv + self.alpha * x_adv.grad.sign()
                # Project back to epsilon ball
                perturbation = torch.clamp(x_adv - x, -self.epsilon, self.epsilon)
                x_adv = torch.clamp(x + perturbation, 0, 1)
            
            x_adv.grad.zero_()
        
        return x_adv.detach()
    
    def adversarial_training_step(self, model, x: np.ndarray, y: np.ndarray, optimizer) -> float:
        """One step of adversarial training"""
        import torch
        
        # Generate adversarial examples
        x_adv = self.generate_adversarial_example(model, x, y)
        
        # Train on both clean and adversarial examples
        model.train()
        
        # Clean loss
        output_clean = model(x)
        loss_clean = torch.nn.functional.cross_entropy(output_clean, y)
        
        # Adversarial loss
        output_adv = model(x_adv)
        loss_adv = torch.nn.functional.cross_entropy(output_adv, y)
        
        # Combined loss
        loss = 0.5 * loss_clean + 0.5 * loss_adv
        
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        
        return loss.item()
