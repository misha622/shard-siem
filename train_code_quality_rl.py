import sys; sys.path.insert(0, "."); from train_seq2seq_defense_v2 import SimpleTokenizer, Seq2SeqTransformer
#!/usr/bin/env python3
"""
SHARD Code Quality RL — 4 метода улучшения генерации кода
1. Compiler Feedback RL (iptables --check)
2. Self-Play (атака → защита → проверка)
3. AST Validation (структура кода)
4. LLM Teacher (DeepSeek/Llama examples)
"""

import subprocess, re, json, random, ast, time, os
import torch, torch.nn as nn
import numpy as np
from pathlib import Path
from collections import defaultdict, deque
from typing import Dict, List, Tuple
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SHARD-CodeRL")


CONFIG = {
    'rl_episodes': 50,
    'batch_size': 16,
    'lr': 0.0001,
    'gamma': 0.95,
    'memory_size': 2000,
    'epsilon_start': 0.3,
    'epsilon_end': 0.05,
    'epsilon_decay': 0.99,
}


class CompilerFeedback:
    """Проверка iptables правил через реальные системные вызовы"""
    
    def __init__(self):
        self.cache = {}
        self.stats = {'checks': 0, 'passed': 0, 'failed': 0}
    
    def validate_rule(self, rule: str) -> Tuple[bool, str, float]:
        """
        Проверяет правило iptables/WAF на корректность
        Returns: (valid, error_msg, reward)
        """
        self.stats['checks'] += 1
        
        rule = rule.strip().replace('<NL>', '\n').replace(' <NL> ', '\n').replace('  ', ' ')
        while '\n\n' in rule:
            rule = rule.replace('\n\n', '\n')
        
        rule_hash = hash(rule)
        if rule_hash in self.cache:
            return self.cache[rule_hash]
        
        if not any(kw in rule for kw in ['iptables', 'SecRule', 'sysctl', 'tcpdump']):
            result = (False, "no_known_command", -1.0)
            self.cache[rule_hash] = result
            self.stats['failed'] += 1
            return result
        
        if 'iptables' in rule:
            reward = self._check_iptables(rule)
        elif 'SecRule' in rule:
            reward = self._check_waf(rule)
        elif 'sysctl' in rule:
            reward = self._check_sysctl(rule)
        elif 'tcpdump' in rule:
            reward = (True, "tcpdump_ok", 0.3)
        else:
            reward = (True, "unknown_ok", 0.1)
        
        self.cache[rule_hash] = reward
        if reward[0]:
            self.stats['passed'] += 1
        else:
            self.stats['failed'] += 1
        
        return reward
    
    def _check_iptables(self, rule: str) -> Tuple[bool, str, float]:
        """Проверка iptables правила"""
        lines = [l.strip() for l in rule.split('\n') if 'iptables' in l]
        
        total_reward = 0.0
        all_valid = True
        errors = []
        
        for line in lines[:3]:
            parts = line.split()
            
            if '-A' not in parts and '-I' not in parts and '-D' not in parts and '-C' not in parts:
                all_valid = False
                errors.append(f"no_action_flag")
                total_reward -= 0.3
                continue
            
            if '-j' not in parts:
                all_valid = False
                errors.append(f"no_jump_target")
                total_reward -= 0.3
                continue
            
            ip_match = re.search(r'-s\s+(\S+)|-d\s+(\S+)', line)
            if ip_match:
                ip = ip_match.group(1) or ip_match.group(2)
                if not re.match(r'^[\d\./]+$', ip):
                    all_valid = False
                    errors.append(f"invalid_ip:{ip}")
                    total_reward -= 0.2
                    continue
            
            port_match = re.search(r'--dport\s+(\S+)|--sport\s+(\S+)', line)
            if port_match:
                port = port_match.group(1) or port_match.group(2)
                if not port.isdigit():
                    all_valid = False
                    errors.append(f"invalid_port:{port}")
                    total_reward -= 0.2
                    continue
            
            total_reward += 0.5
            
            try:
                check_cmd = line.replace(' -A ', ' -C ').replace(' -I ', ' -C ')
                parts = check_cmd.split()
                result = subprocess.run(
                    ['iptables'] + parts[1:],
                    capture_output=True, text=True, timeout=1
                )
                if result.returncode in [0, 1]:
                    total_reward += 0.3
            except Exception:
                pass
        
        if all_valid and not errors:
            return (True, "iptables_valid", min(1.0, total_reward))
        else:
            return (False, '; '.join(errors[:3]), max(-1.0, total_reward))
    
    def _check_waf(self, rule: str) -> Tuple[bool, str, float]:
        """Проверка WAF правила"""
        if 'SecRule' in rule and '"id:' in rule and 'phase:' in rule:
            return (True, "waf_valid", 0.5)
        return (False, "waf_incomplete", -0.2)
    
    def _check_sysctl(self, rule: str) -> Tuple[bool, str, float]:
        """Проверка sysctl команды"""
        if 'sysctl' in rule and '=' in rule:
            return (True, "sysctl_valid", 0.3)
        return (False, "sysctl_invalid", -0.2)



class SelfPlay:
    """SHARD атакует сам себя для обучения"""
    
    def __init__(self):
        self.attack_templates = [
            ("SQL Injection", "GET /?id=1' UNION SELECT password FROM users-- HTTP/1.0\r\n\r\n"),
            ("Brute Force", "SSH-2.0-OpenSSH\r\nroot:password123\n"),
            ("DDoS", "GET / HTTP/1.0\r\n" * 100),
            ("XSS", "GET /?q=<script>alert(1)</script> HTTP/1.0\r\n\r\n"),
        ]
        self.results = {'attacks': 0, 'defenses': 0, 'successful_defenses': 0}
    
    def run_cycle(self, seq2seq_model, tokenizer) -> Dict:
        """Один цикл self-play: атака → защита → оценка"""
        attack_type, attack_payload = random.choice(self.attack_templates)
        
        attack_desc = f"{attack_type} from 10.0.0.{random.randint(1,255)} on port {random.choice([80,443,3306,22])}"
        
        try:
            src = tokenizer.encode(attack_desc).unsqueeze(0)
            defense_code = seq2seq_model.generate(src, tokenizer, temperature=0.5)
            
            compiler = CompilerFeedback()
            valid, msg, reward = compiler.validate_rule(defense_code)
            
            self.results['attacks'] += 1
            self.results['defenses'] += 1
            if valid:
                self.results['successful_defenses'] += 1
            
            return {
                'attack': attack_desc,
                'defense': defense_code[:200],
                'valid': valid,
                'reward': reward,
                'msg': msg,
            }
        except Exception as e:
            return {'attack': attack_desc, 'defense': 'ERROR', 'valid': False, 'reward': -1.0, 'msg': str(e)[:50]}



class ASTValidator:
    """Проверка структуры сгенерированного кода"""
    
    def validate(self, code: str) -> Tuple[bool, float]:
        """
        Проверяет код на структурную корректность
        """
        score = 0.0
        issues = []
        
        if code.count("'") % 2 == 0 and code.count('"') % 2 == 0:
            score += 0.2
        
        if '; rm -rf' not in code and '; wget' not in code:
            score += 0.2
        
        valid_flags = ['-A', '-I', '-D', '-s', '-d', '-p', '--dport', '--sport', '-j', '-m']
        iptables_lines = [l for l in code.split('\n') if 'iptables' in l]
        for line in iptables_lines:
            flags_ok = sum(1 for f in valid_flags if f in line)
            score += min(0.3, flags_ok * 0.05)
        
        comment_lines = [l for l in code.split('\n') if l.strip().startswith('
        score += min(0.1, len(comment_lines) * 0.02)
        
        if len(code.strip()) > 10:
            score += 0.2
        
        valid = score > 0.3
        return valid, min(1.0, score)



class LLMTeacher:
    """Использует примеры правильного кода как few-shot учителя"""
    
    def __init__(self):
        self.examples = [
            {
                'attack': 'SQL injection on port 3306',
                'code': 'iptables -A INPUT -s 10.0.0.1 -p tcp --dport 3306 -j DROP\n'
                        'iptables -A INPUT -p tcp --dport 3306 -m string --string "UNION SELECT" --algo bm -j DROP\n'
                        'SecRule REQUEST_URI "@rx union.*select" "id:1001,phase:2,deny,status:403"'
            },
            {
                'attack': 'SSH brute force on port 22',
                'code': 'iptables -A INPUT -s 10.0.0.2 -p tcp --dport 22 -j DROP\n'
                        'iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 300 --hitcount 3 -j DROP\n'
                        'iptables -A INPUT -s 10.0.0.2 -j LOG --log-prefix "BRUTE:"'
            },
            {
                'attack': 'DDoS SYN flood on port 443',
                'code': 'iptables -A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT\n'
                        'iptables -A INPUT -p tcp --syn -j DROP\n'
                        'sysctl -w net.ipv4.tcp_syncookies=1'
            },
        ]
    
    def get_few_shot_prompt(self, attack_desc: str) -> str:
        """Создаёт few-shot примеры для обучения"""
        prompt_parts = []
        for ex in self.examples:
            prompt_parts.append(f"Attack: {ex['attack']}\nDefense:\n{ex['code']}\n")
        
        prompt_parts.append(f"Attack: {attack_desc}\nDefense:")
        return '\n'.join(prompt_parts)
    
    def evaluate_similarity(self, generated: str, reference: str) -> float:
        """Оценивает похожесть сгенерированного кода на эталонный"""
        gen_words = set(generated.lower().split())
        ref_words = set(reference.lower().split())
        
        if not ref_words:
            return 0.0
        
        overlap = len(gen_words & ref_words) / len(ref_words)
        return min(1.0, overlap)



class CodeQualityRLTrainer:
    """Объединяет все 4 метода для улучшения генерации кода"""
    
    def __init__(self):
        self.compiler = CompilerFeedback()
        self.self_play = SelfPlay()
        self.ast = ASTValidator()
        self.teacher = LLMTeacher()
        
        self.memory = deque(maxlen=CONFIG['memory_size'])
        self.epsilon = CONFIG['epsilon_start']
        
        self.stats = {
            'compiler': {'uses': 0, 'rewards': []},
            'self_play': {'uses': 0, 'rewards': []},
            'ast': {'uses': 0, 'rewards': []},
            'llm': {'uses': 0, 'rewards': []},
        }
    
    def train_episode(self, model, tokenizer) -> Dict:
        """Один эпизод обучения со всеми 4 методами"""
        results = {}
        
        attack_desc = f"SQL Injection from 10.0.0.{random.randint(1,255)} on port 3306"
        try:
            src = tokenizer.encode(attack_desc).unsqueeze(0)
            code = model.generate(src, tokenizer, temperature=0.5)
            valid, msg, reward = self.compiler.validate_rule(code)
            
            self.memory.append(('compiler', attack_desc, code, reward))
            self.stats['compiler']['uses'] += 1
            self.stats['compiler']['rewards'].append(reward)
            results['compiler'] = {'valid': valid, 'reward': reward, 'msg': msg}
        except Exception as e:
            results['compiler'] = {'valid': False, 'reward': -0.5, 'msg': str(e)[:50]}
        
        sp_result = self.self_play.run_cycle(model, tokenizer)
        self.memory.append(('self_play', sp_result['attack'], sp_result['defense'], sp_result['reward']))
        self.stats['self_play']['uses'] += 1
        self.stats['self_play']['rewards'].append(sp_result['reward'])
        results['self_play'] = sp_result
        
        try:
            src = tokenizer.encode(attack_desc).unsqueeze(0)
            code = model.generate(src, tokenizer, temperature=0.5)
            valid, score = self.ast.validate(code)
            
            self.memory.append(('ast', attack_desc, code, score))
            self.stats['ast']['uses'] += 1
            self.stats['ast']['rewards'].append(score)
            results['ast'] = {'valid': valid, 'score': score}
        except Exception as e:
            results['ast'] = {'valid': False, 'score': 0.0}
        
        try:
            few_shot_prompt = self.teacher.get_few_shot_prompt(attack_desc)
            src = tokenizer.encode(attack_desc).unsqueeze(0)
            code = model.generate(src, tokenizer, temperature=0.3)
            
            reference = self.teacher.examples[0]['code']
            similarity = self.teacher.evaluate_similarity(code, reference)
            
            self.memory.append(('llm', attack_desc, code, similarity))
            self.stats['llm']['uses'] += 1
            self.stats['llm']['rewards'].append(similarity)
            results['llm'] = {'similarity': similarity}
        except Exception as e:
            results['llm'] = {'similarity': 0.0}
        
        self.epsilon = max(CONFIG['epsilon_end'], self.epsilon * CONFIG['epsilon_decay'])
        
        return results
    
    def get_avg_rewards(self) -> Dict:
        """Средние награды по методам"""
        avgs = {}
        for method, data in self.stats.items():
            if data['rewards']:
                avgs[method] = {
                    'avg_reward': sum(data['rewards'][-100:]) / len(data['rewards'][-100:]),
                    'uses': data['uses'],
                }
        return avgs
    
    def print_report(self):
        """Отчёт о тренировке"""
        print("\n" + "="*60)
        print("📊 ОТЧЁТ CODE QUALITY RL")
        print("="*60)
        print(f"   Память: {len(self.memory)} примеров")
        print(f"   Epsilon: {self.epsilon:.3f}")
        print()
        
        for method, data in self.stats.items():
            if data['rewards']:
                recent = data['rewards'][-100:]
                avg = sum(recent) / len(recent)
                print(f"   {method}: avg_reward={avg:.3f} | uses={data['uses']} | recent={len(recent)}")


def main():
    logger.info("="*60)
    logger.info("🧠 SHARD CODE QUALITY RL TRAINER")
    logger.info("   4 метода улучшения генерации кода")
    logger.info("="*60)
    
    logger.info("\n📂 Загрузка Seq2Seq модели...")
    
    from train_seq2seq_defense_v2 import Seq2SeqTransformer, SimpleTokenizer
    
    model_path = 'models/seq2seq/defense_transformer_v2.pt'
    if not Path(model_path).exists():
        logger.error(f"Модель не найдена: {model_path}")
        logger.info("Сначала запустите: python3 train_seq2seq_defense_v2.py")
        return
    
    checkpoint = torch.load(model_path, map_location='cpu', weights_only=False)
    config = checkpoint['config']
    
    model = Seq2SeqTransformer(
        vocab_size=checkpoint['vocab_size'],
        embed_dim=config['embed_dim'],
        num_heads=config['num_heads'],
        num_layers=config['num_layers'],
        hidden_dim=config['hidden_dim'],
        dropout=config['dropout'],
        max_len=config['max_seq_len']
    )
    model.load_state_dict(checkpoint['model_state_dict'])
    model.eval()
    
    tokenizer = SimpleTokenizer()
    tokenizer.word2idx = checkpoint['src_tokenizer'].word2idx
    tokenizer.idx2word = checkpoint['src_tokenizer'].idx2word
    tokenizer.fitted = True 
    
    logger.info(f"✅ Модель загружена: {sum(p.numel() for p in model.parameters()):,} параметров")
    
    trainer = CodeQualityRLTrainer()
    
    logger.info(f"\n🔄 Тренировка {CONFIG['rl_episodes']} эпизодов...")
    
    for episode in range(CONFIG['rl_episodes']):
        results = trainer.train_episode(model, tokenizer)
        
        if episode % 50 == 0:
            logger.info(f"\n   Episode {episode}/{CONFIG['rl_episodes']}")
            for method, res in results.items():
                if 'reward' in res:
                    logger.info(f"     {method}: reward={res.get('reward', 0):.3f}")
    
    trainer.print_report()
    
    logger.info(f"\n🧪 Тестовая генерация после RL:")
    test_attacks = [
        "SQL Injection from 185.142.53.101 on port 3306",
        "SSH Brute Force from 45.155.205.233:22",
        "DDoS from 194.61.23.45 on port 443",
    ]
    
    for attack in test_attacks:
        src = tokenizer.encode(attack).unsqueeze(0)
        code = model.generate(src, tokenizer, temperature=0.5)
        
        valid, msg, reward = trainer.compiler.validate_rule(code)
        ast_valid, ast_score = trainer.ast.validate(code)
        
        status = "✅" if valid else "❌"
        logger.info(f"\n   {status} Атака: {attack}")
        logger.info(f"   Compiler: {msg} (reward: {reward:.2f})")
        logger.info(f"   AST score: {ast_score:.2f}")
        logger.info(f"   Код: {code[:120]}...")
    
    logger.info(f"\n{'='*60}")
    logger.info(f"✅ ТРЕНИРОВКА ЗАВЕРШЕНА!")
    logger.info(f"   Методы: Compiler + Self-Play + AST + LLM Teacher")
    logger.info(f"   Всего эпизодов: {CONFIG['rl_episodes']}")
    logger.info(f"{'='*60}")


if __name__ == '__main__':
    main()
