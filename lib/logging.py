import logging
import os

DEFAULT_LOG_LEVEL = "INFO"

LOGLEVEL = os.environ.get('LOGLEVEL', DEFAULT_LOG_LEVEL).upper()

class ColoredFormatter(logging.Formatter):
    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

colored_loggers = {}

def get_colored_logger(name):
    global colored_loggers
    if name in colored_loggers:
        return colored_loggers[name]
    else:
        logger = logging.getLogger(name)
        logger.propagate = False
        logger.setLevel(level=LOGLEVEL)
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(ColoredFormatter())
        logger.addHandler(ch)        
        colored_loggers[name] = logger 
        return logger
