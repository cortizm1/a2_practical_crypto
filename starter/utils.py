import datetime

import logging

logging.basicConfig(filename='a2.log', level=logging.ERROR)
logger = logging.getLogger(__name__)

def function_logger(func, *args): #
    def wrapper(args):
        try:
            t = datetime.datetime.now()
            logger.info(f"{t}\tExecuting {func.__name__}.") 
            return func(args)
        except Exception as e:
                error_writer(e, description=f"Wrapper error.")
    return wrapper

# tuple unpacking kwargs and all of that didn't work for a two param function... brittle code but I'm rusty
def function_logger_too(func, *args, **kwargs): #
    def wrapper(args, kwargs):
        try:
            t = datetime.datetime.now()
            logger.info(f"{t}\tExecuting {func.__name__}.") 
            return func(args, kwargs)
        except Exception as e:
                error_writer(e, description=f"Wrapper error.")
    return wrapper

def error_writer(e:Exception, description:str):
    t = datetime.datetime.now()
    logger.error(f"{t}\t{description}\t{e}")