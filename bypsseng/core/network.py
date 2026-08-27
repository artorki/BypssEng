import aiohttp
import logging
from typing import Optional, List
from aiohttp.abc import AbstractResolver

logger = logging.getLogger("NetAnalyzer")


try:
    import aiodns

    RESOLVER_CLASS = aiohttp.AsyncResolver
    logger.debug("aiodns is installed. Using AsyncResolver for better performance.")
except ImportError:
    RESOLVER_CLASS = aiohttp.DefaultResolver
    logger.warning("aiodns is not installed. Using default resolver (may be slower).")


def get_resolver(nameservers: Optional[List[str]] = None) -> AbstractResolver:
    if RESOLVER_CLASS == aiohttp.DefaultResolver:
        try:
            return aiohttp.DefaultResolver(nameservers=nameservers)
        except TypeError:

            return aiohttp.DefaultResolver()
    return RESOLVER_CLASS(nameservers=nameservers)
