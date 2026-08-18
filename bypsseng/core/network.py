import aiohttp
import sys

try:
    import aiodns
    RESOLVER_CLASS = aiohttp.AsyncResolver
except ImportError:
    print("Warning: 'aiodns' is not installed. Using default resolver.")
    RESOLVER_CLASS = aiohttp.DefaultResolver

def get_resolver(nameservers=None):
    if RESOLVER_CLASS == aiohttp.DefaultResolver:
        try:
            return aiohttp.DefaultResolver(nameservers=nameservers)
        except TypeError:
            return aiohttp.DefaultResolver()
    return RESOLVER_CLASS(nameservers=nameservers)
