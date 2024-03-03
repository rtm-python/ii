"""
"""

import logging

logger = logging.getLogger('AGENT')
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter(
    '%(asctime)s | %(name)s:%(levelname)s | %(message)s | %(module)s:%(funcName)s:%(lineno)d')
handler.setFormatter(formatter)
handler.setLevel(logging.INFO)
logger.addHandler(handler)
