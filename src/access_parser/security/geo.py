import geoip2.database
from typing import Dict, Optional

class GeoResolver:
    """
    Wrapper for MaxMind GeoIP2 database lookups.
    """
    def __init__(self, db_path: Optional[str]):
        self.db_path = db_path

    def resolve(self, ip_address: str) -> Dict[str, str]:
        """
        Resolves an IP address to a country and city.
        Returns a dictionary with 'country' and 'city' keys, or empty if resolution fails.
        """
        if not self.db_path:
            return {}
            
        try:
            with geoip2.database.Reader(self.db_path) as reader:
                response = reader.city(ip_address)
                return {
                    "country": response.country.iso_code,
                    "city": response.city.name
                }
        except Exception:
            return {}
