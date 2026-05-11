# Contributing to SHARD

Fork → branch → code → test → commit → push → PR

## Dev Setup
```bash
git clone https://github.com/misha622/shard-siem.git
cd shard-siem && pip install -r requirements.txt
python3 run_shard.py --no-capture
```

## Tests
```bash
pytest test_shard_defense.py -v
```
