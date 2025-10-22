# src/utils/crypto.py
"""
Cryptographic utilities for evidence integrity
"""
import hashlib
from typing import Tuple


def compute_hash(data: bytes, algorithm: str = 'sha256') -> str:
    """
    Compute hash of data using specified algorithm
    
    Args:
        data: Bytes to hash
        algorithm: Hash algorithm ('sha256', 'md5', 'sha1')
    
    Returns:
        Hexadecimal hash string
    """
    if algorithm == 'sha256':
        return hashlib.sha256(data).hexdigest()
    elif algorithm == 'md5':
        return hashlib.md5(data).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(data).hexdigest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def compute_multiple_hashes(data: bytes) -> Tuple[str, str]:
    """
    Compute both SHA256 and MD5 hashes
    
    Args:
        data: Bytes to hash
    
    Returns:
        Tuple of (sha256_hash, md5_hash)
    """
    sha256_hash = hashlib.sha256(data).hexdigest()
    md5_hash = hashlib.md5(data).hexdigest()
    return sha256_hash, md5_hash


def verify_hash(data: bytes, expected_hash: str, algorithm: str = 'sha256') -> bool:
    """
    Verify data matches expected hash
    
    Args:
        data: Bytes to verify
        expected_hash: Expected hash value
        algorithm: Hash algorithm used
    
    Returns:
        True if hash matches, False otherwise
    """
    computed_hash = compute_hash(data, algorithm)
    return computed_hash.lower() == expected_hash.lower()


class CryptoUtils:
    """Cryptographic utilities for evidence handling"""
    
    @staticmethod
    def hash_data(data: bytes) -> Tuple[str, str]:
        """
        Generate SHA256 and MD5 hashes for data
        
        Returns:
            Tuple of (sha256_hash, md5_hash)
        """
        return compute_multiple_hashes(data)
    
    @staticmethod
    def verify_integrity(data: bytes, sha256_hash: str, md5_hash: str) -> bool:
        """
        Verify data integrity using stored hashes
        
        Args:
            data: Data to verify
            sha256_hash: Expected SHA256 hash
            md5_hash: Expected MD5 hash
        
        Returns:
            True if both hashes match
        """
        computed_sha256, computed_md5 = compute_multiple_hashes(data)
        return (computed_sha256.lower() == sha256_hash.lower() and 
                computed_md5.lower() == md5_hash.lower())
    
    @staticmethod
    def generate_checksum(data: bytes, algorithm: str = 'sha256') -> str:
        """Generate checksum for data"""
        return compute_hash(data, algorithm)