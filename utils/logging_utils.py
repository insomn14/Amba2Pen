import logging
import colorlog

def setup_logging(log_level):
    # Clear any existing handlers to prevent duplicates
    logger = logging.getLogger()
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    log_colors = {
        'DEBUG': 'blue',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red'
    }
    
    formatter = colorlog.ColoredFormatter(
        '[%(asctime)s] [%(log_color)s%(levelname)s%(reset)s] %(message)s',
        datefmt='%H:%M:%S',
        log_colors=log_colors,
    )
    
    handler = colorlog.StreamHandler()
    handler.setFormatter(formatter)
    
    logger.addHandler(handler)
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Prevent propagation to root logger to avoid duplicate messages
    logger.propagate = False
