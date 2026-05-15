#!/bin/bash
# Загрузка датасетов для SHARD
mkdir -p data/datasets

echo "📦 Скачивание CIC-IDS-2017..."
wget -q --show-progress -P data/datasets/ \
  http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/MachineLearningCSV.zip

echo "📦 Скачивание UNSW-NB15..."
wget -q --show-progress -P data/datasets/ \
  https://cloudstor.aarnet.edu.au/plus/s/2DhnLGDdEECo4ys/download

echo "✅ Готово. Распакуйте архивы в data/datasets/"
