#!/usr/bin/env python3
"""SHARD Time-Series Anomaly Detector — тренды и сезонность атак (модель #21)"""
import numpy as np, logging
logger = logging.getLogger("SHARD-Prophet")
try:
    from prophet import Prophet
    HAS_PROPHET = True
except ImportError:
    HAS_PROPHET = False
    logger.warning("pip install prophet")

class TimeSeriesDetector:
    def __init__(self, interval_width=0.99):
        self.model = Prophet(interval_width=interval_width, yearly_seasonality=False, weekly_seasonality=True, daily_seasonality=True) if HAS_PROPHET else None
        self.is_fitted = False
    
    def fit(self, timestamps, values):
        if self.model is None: return None
        df = pd.DataFrame({'ds': pd.to_datetime(timestamps, unit='s'), 'y': values})
        self.model.fit(df)
        self.is_fitted = True
        return {'samples': len(df)}
    
    def predict(self, timestamps):
        if not self.is_fitted: return np.zeros(len(timestamps))
        future = pd.DataFrame({'ds': pd.to_datetime(timestamps, unit='s')})
        forecast = self.model.predict(future)
        return forecast['yhat'].values, forecast['yhat_upper'].values - forecast['yhat'].values

logger.info("✅ TimeSeries Detector ready (model #21)")
