import pytest
from unittest.mock import MagicMock, patch
from src.access_parser.security.geo import GeoResolver

@patch('geoip2.database.Reader')
def test_geo_lookup_success(mock_reader_class):
    mock_reader = MagicMock()
    mock_reader_class.return_value.__enter__.return_value = mock_reader
    
    mock_response = MagicMock()
    mock_response.country.iso_code = 'US'
    mock_response.city.name = 'Austin'
    mock_reader.city.return_value = mock_response
    
    resolver = GeoResolver('fake.mmdb')
    result = resolver.resolve('8.8.8.8')
    
    assert result['country'] == 'US'
    assert result['city'] == 'Austin'

@patch('geoip2.database.Reader')
def test_geo_lookup_failure(mock_reader_class):
    mock_reader = MagicMock()
    mock_reader_class.return_value.__enter__.return_value = mock_reader
    mock_reader.city.side_effect = Exception("Not found")
    
    resolver = GeoResolver('fake.mmdb')
    result = resolver.resolve('127.0.0.1')
    
    assert result == {}
