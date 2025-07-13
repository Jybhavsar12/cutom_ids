import logging
import os

# Ensure the data directory exists
os.makedirs('data', exist_ok=True)

logging.basicConfig(
    filename='data/ids_alerts.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger()

