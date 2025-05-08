import logging
import colorlog

def setup_logging(log_level):
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
    logger = logging.getLogger()
    logger.addHandler(handler)
    logger.setLevel(log_level)
