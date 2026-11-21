import datetime
import functools
import logging

logging.basicConfig(filename='a2.log', level=logging.ERROR)
logger = logging.getLogger(__name__)


def error_writer(e: Exception, description: str):
    t = datetime.datetime.now()
    logger.error(f"{t}\t{description}\t{e}")


def logged(func):
    """Log entry and any exception, then re-raise it unchanged.

    The decorator never swallows: the spec gives each exception a meaning
    (ValueError from pkcs7_unpad, DecodeError -> discard, PeerKeyUnavailable
    -> error event), so the function that knows the spec decides what to
    catch. Everything else must crash loudly so you find it.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logger.info(f"{datetime.datetime.now()}\tExecuting {func.__name__}.")
        try:
            return func(*args, **kwargs)
        except Exception as e:
            error_writer(e, description=f"{func.__name__} raised")
            raise
    return wrapper


# Old names kept so existing decorators in padding.py / protocol.py keep working.
function_logger = logged
function_logger_too = logged
