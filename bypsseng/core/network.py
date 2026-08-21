


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
    """
    Returns a configured DNS resolver instance.
    Prefers aiodns if available for better performance and reliability.
    
    Args:
        nameservers: List of DNS server IPs to use (e.g., ["1.1.1.1", "8.8.8.8"]).
        
    Returns:
        An instance of AbstractResolver.
    """
    if RESOLVER_CLASS == aiohttp.DefaultResolver:
        try: 
            return aiohttp.DefaultResolver(nameservers=nameservers)
        except TypeError: 

            return aiohttp.DefaultResolver()
    return RESOLVER_CLASS(nameservers=nameservers)