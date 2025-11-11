#!/usr/bin/env python3
"""
ISO Download, Verification, and Upload Script for Scale Computing Hypercore
Downloads an ISO, verifies checksum, and uploads to Hypercore

Version: 1.1.0
Author: Wyatt
Repository: https://github.com/yourusername/hypercore-iso-uploader

SECURITY WARNING:
This script disables SSL certificate verification for self-signed certificates.
Only use on trusted networks (e.g., internal LAN).
Do NOT use over public/untrusted networks as it's vulnerable to man-in-the-middle attacks.
"""

__version__ = "1.1.0"

import hashlib
import requests
import sys
import os
import getpass
import tempfile
import shutil
from pathlib import Path
from typing import Tuple, Optional
from urllib.parse import urlparse
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Constants
DOWNLOAD_CHUNK_SIZE = 8192  # 8KB chunks for downloading
HASH_CHUNK_SIZE = 4096      # 4KB chunks for hashing
PROGRESS_BAR_LENGTH = 40    # Character width of progress bar


def validate_url(url: str, description: str = "URL") -> bool:
    """
    Validate that a URL is properly formatted and uses HTTP/HTTPS
    
    Args:
        url: URL string to validate
        description: Description of the URL for error messages
    
    Returns:
        True if valid, False otherwise
    """
    try:
        parsed = urlparse(url)
        
        # Check if URL has a scheme and netloc
        if not parsed.scheme or not parsed.netloc:
            print(f"Error: Invalid {description} - missing protocol or domain")
            return False
        
        # Warn if not HTTPS (but allow HTTP for testing)
        if parsed.scheme not in ['http', 'https']:
            print(f"Error: Invalid {description} - must use http or https")
            return False
        
        if parsed.scheme == 'http':
            print(f"Warning: {description} uses unencrypted HTTP connection")
        
        return True
        
    except Exception as e:
        print(f"Error: Invalid {description} - {e}")
        return False


def validate_iso_url(url: str) -> bool:
    """
    Validate ISO URL and ensure filename ends with .iso
    
    Args:
        url: ISO URL to validate
    
    Returns:
        True if valid, False otherwise
    """
    if not validate_url(url, "ISO URL"):
        return False
    
    # Extract filename from URL
    filename = os.path.basename(urlparse(url).path)
    
    if not filename.lower().endswith('.iso'):
        print(f"Error: ISO URL must point to a file ending with .iso (got: {filename})")
        print("Note: Hypercore requires ISO files to have .iso extension")
        return False
    
    return True


def get_credentials() -> Tuple[str, str, str]:
    """
    Get Hypercore credentials from environment variables or prompt user
    
    Returns:
        Tuple of (cluster_url, username, password)
    
    Raises:
        SystemExit: If required credentials are not provided
    """
    # Try environment variables first
    cluster = os.environ.get('HYPERCORE_CLUSTER')
    username = os.environ.get('HYPERCORE_USER')
    password = os.environ.get('HYPERCORE_PASSWORD')
    
    # Prompt for missing values
    if not cluster:
        cluster = input("Enter Hypercore cluster IP/hostname: ").strip()
        if not cluster:
            print("Error: Cluster address is required")
            sys.exit(1)
    
    # Ensure cluster has https:// prefix
    if not cluster.startswith('http'):
        cluster = f"https://{cluster}"
    
    # Validate cluster URL
    if not validate_url(cluster, "Hypercore cluster URL"):
        sys.exit(1)
    
    if not username:
        username = input("Enter Hypercore username: ").strip()
        if not username:
            print("Error: Username is required")
            sys.exit(1)
    
    if not password:
        password = getpass.getpass("Enter Hypercore password: ")
        if not password:
            print("Error: Password is required")
            sys.exit(1)
    
    print()
    return cluster, username, password


def format_bytes(bytes_value: int) -> str:
    """
    Format bytes as human-readable string
    
    Args:
        bytes_value: Number of bytes
    
    Returns:
        Formatted string (e.g., "123.4 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"


def print_progress_bar(current: int, total: int, prefix: str = "") -> None:
    """
    Print a progress bar to stdout
    
    Args:
        current: Current progress value
        total: Total/maximum value
        prefix: Optional prefix string
    """
    if total == 0:
        return
    
    percent = (current / total) * 100
    filled = int(PROGRESS_BAR_LENGTH * current / total)
    bar = '=' * filled + '-' * (PROGRESS_BAR_LENGTH - filled)
    
    current_str = format_bytes(current)
    total_str = format_bytes(total)
    
    print(f"\r{prefix}[{bar}] {percent:.1f}% ({current_str}/{total_str})", end='', flush=True)


def download_file(url: str, destination: Path) -> Path:
    """
    Download a file from URL to destination with progress indicator
    
    Args:
        url: URL to download from
        destination: Local file path to save to
    
    Returns:
        Path to downloaded file
    
    Raises:
        SystemExit: If download fails
    """
    print(f"Downloading: {url}")
    
    try:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        
        # Get file size if available
        total_size = int(response.headers.get('content-length', 0))
        
        with open(destination, 'wb') as f:
            if total_size == 0:
                # No content-length header, download without progress
                f.write(response.content)
                print("Download complete (size unknown)")
            else:
                # Download with progress bar
                downloaded = 0
                print(f"File size: {format_bytes(total_size)}")
                
                for chunk in response.iter_content(chunk_size=DOWNLOAD_CHUNK_SIZE):
                    if chunk:  # Filter out keep-alive chunks
                        f.write(chunk)
                        downloaded += len(chunk)
                        print_progress_bar(downloaded, total_size)
                
                print()  # New line after progress bar
        
        print(f"Saved to: {destination}\n")
        return destination
        
    except requests.exceptions.Timeout:
        print(f"Error: Download timed out after 30 seconds")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"Error downloading file: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"HTTP Status: {e.response.status_code}")
        sys.exit(1)


def calculate_sha256(filepath: Path) -> str:
    """
    Calculate SHA256 checksum of a file
    
    Args:
        filepath: Path to file to hash
    
    Returns:
        Hexadecimal string of SHA256 hash
    """
    print(f"Calculating SHA256 checksum for {filepath.name}...")
    
    sha256_hash = hashlib.sha256()
    file_size = filepath.stat().st_size
    processed = 0
    
    with open(filepath, "rb") as f:
        # Read in chunks to handle large files
        for chunk in iter(lambda: f.read(HASH_CHUNK_SIZE), b""):
            sha256_hash.update(chunk)
            processed += len(chunk)
            print_progress_bar(processed, file_size, "Hashing: ")
    
    print()  # New line after progress bar
    checksum = sha256_hash.hexdigest()
    print(f"Calculated checksum: {checksum}\n")
    return checksum


def parse_checksum_file(checksum_path: Path, iso_filename: str) -> Optional[str]:
    """
    Parse a checksum file to find the hash for our ISO
    Supports multiple formats:
    - SHA256 (filename) = hash
    - hash  filename
    - hash *filename
    
    Args:
        checksum_path: Path to checksum file
        iso_filename: Name of ISO file to find checksum for
    
    Returns:
        Expected checksum string or None if not found
    """
    print(f"Parsing checksum file: {checksum_path.name}")
    
    try:
        with open(checksum_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#') or line.startswith('-----'):
                    continue
                
                # Format 1: SHA256 (filename) = hash
                if '(' in line and ')' in line and '=' in line:
                    try:
                        # Extract filename from parentheses
                        start = line.find('(')
                        end = line.find(')')
                        filename = line[start+1:end].strip()
                        
                        # Extract hash after =
                        checksum = line.split('=', 1)[1].strip()
                        
                        if filename == iso_filename:
                            print(f"Found checksum for {iso_filename}: {checksum}\n")
                            return checksum
                    except (ValueError, IndexError):
                        # Malformed line, skip it
                        continue
                
                # Format 2: <hash>  <filename> or <hash> *<filename>
                else:
                    parts = line.split(None, 1)  # Split on whitespace, max 2 parts
                    if len(parts) >= 2:
                        checksum = parts[0]
                        # Remove leading * if present (indicates binary mode)
                        filename = parts[1].lstrip('*').strip()
                        
                        if filename == iso_filename:
                            print(f"Found checksum for {iso_filename}: {checksum}\n")
                            return checksum
    
    except UnicodeDecodeError:
        print(f"Warning: Checksum file contains invalid UTF-8 characters\n")
        return None
    except IOError as e:
        print(f"Error reading checksum file: {e}\n")
        return None
    
    print(f"Warning: Could not find checksum for {iso_filename} in checksum file\n")
    return None


def verify_checksum(iso_path: Path, checksum_path: Path) -> bool:
    """
    Verify ISO file against checksum file
    
    Args:
        iso_path: Path to ISO file
        checksum_path: Path to checksum file
    
    Returns:
        True if checksum matches, False otherwise
    """
    iso_filename = iso_path.name
    
    # Parse expected checksum from file
    expected_checksum = parse_checksum_file(checksum_path, iso_filename)
    
    if not expected_checksum:
        print("Error: Could not find expected checksum in file")
        return False
    
    # Calculate actual checksum
    actual_checksum = calculate_sha256(iso_path)
    
    # Compare (case-insensitive)
    if actual_checksum.lower() == expected_checksum.lower():
        print("[PASS] Checksum verification successful")
        return True
    else:
        print("[FAIL] Checksum verification failed")
        print(f"Expected: {expected_checksum}")
        print(f"Got:      {actual_checksum}")
        return False


class ProgressFileWrapper:
    """
    File wrapper that tracks upload progress
    """
    def __init__(self, file_obj, file_size: int):
        self.file_obj = file_obj
        self.file_size = file_size
        self.uploaded = 0
    
    def read(self, size: int = -1):
        """Read from file and update progress"""
        chunk = self.file_obj.read(size)
        if chunk:
            self.uploaded += len(chunk)
            print_progress_bar(self.uploaded, self.file_size, "Uploading: ")
        return chunk
    
    def __len__(self):
        return self.file_size


def upload_to_hypercore(iso_path: Path, cluster_url: str, username: str, password: str) -> bool:
    """
    Upload ISO to Hypercore using three-step process:
    1. Create empty ISO record
    2. Upload ISO data
    3. Mark as ready for insert
    
    Args:
        iso_path: Path to ISO file
        cluster_url: Hypercore cluster URL
        username: API username
        password: API password
    
    Returns:
        True if successful, False otherwise
    """
    iso_filename = iso_path.name
    iso_size = iso_path.stat().st_size
    
    print("=" * 60)
    print("UPLOADING TO HYPERCORE")
    print("=" * 60)
    print()
    print("WARNING: SSL certificate verification is DISABLED")
    print("         Ensure you are on a trusted network")
    print()
    
    # Create session with auth and SSL verification disabled
    session = requests.Session()
    session.auth = (username, password)
    session.verify = False
    session.headers.update({'User-Agent': f'hypercore-iso-uploader/{__version__}'})
    
    iso_uuid = None
    
    try:
        # Step 1: Create empty ISO record
        print(f"Step 1: Creating ISO record for '{iso_filename}'...")
        create_url = f"{cluster_url}/rest/v1/ISO"
        create_data = {
            "name": iso_filename,
            "size": iso_size,
            "readyForInsert": False
        }
        
        response = session.post(create_url, json=create_data, timeout=30)
        response.raise_for_status()
        
        # Get UUID from response
        iso_record = response.json()
        iso_uuid = iso_record.get('uuid') or iso_record.get('UUID') or iso_record.get('createdUUID')
        
        if not iso_uuid:
            print("Error: No UUID returned from ISO creation")
            print(f"Response: {iso_record}")
            return False
        
        print(f"[OK] ISO record created with UUID: {iso_uuid}\n")
        
        # Step 2: Upload ISO data
        print(f"Step 2: Uploading ISO data ({format_bytes(iso_size)})...")
        upload_url = f"{cluster_url}/rest/v1/ISO/{iso_uuid}/data"
        
        with open(iso_path, 'rb') as f:
            file_wrapper = ProgressFileWrapper(f, iso_size)
            headers = {
                'Content-Length': str(iso_size),
                'Content-Type': 'application/octet-stream'
            }
            
            response = session.put(upload_url, data=file_wrapper, headers=headers, timeout=3600)
            print()  # New line after progress bar
            response.raise_for_status()
        
        print("[OK] ISO data uploaded successfully\n")
        
        # Step 3: Mark as ready for insert
        print("Step 3: Marking ISO as ready for insert...")
        update_url = f"{cluster_url}/rest/v1/ISO/{iso_uuid}"
        update_data = {
            "name": iso_filename,
            "readyForInsert": True
        }
        
        response = session.patch(update_url, json=update_data, timeout=30)
        response.raise_for_status()
        
        print("[OK] ISO marked as ready for insert\n")
        print("=" * 60)
        print(f"SUCCESS: ISO '{iso_filename}' uploaded to Hypercore")
        print(f"         UUID: {iso_uuid}")
        print("=" * 60)
        
        return True
        
    except requests.exceptions.Timeout:
        print(f"\nError: Request timed out")
        return False
    except requests.exceptions.HTTPError as e:
        print(f"\nError: HTTP {e.response.status_code}")
        if e.response.status_code == 401:
            print("Authentication failed - check username and password")
        elif e.response.status_code == 403:
            print("Access forbidden - user may lack ISO upload permissions")
        elif e.response.status_code == 500:
            print("Server error - check Hypercore logs")
            print("Note: Ensure filename ends with .iso and cluster has sufficient storage")
        
        try:
            error_detail = e.response.json()
            print(f"Details: {error_detail}")
        except:
            print(f"Response: {e.response.text[:200]}")
        
        return False
    except requests.exceptions.RequestException as e:
        print(f"\nError communicating with Hypercore: {e}")
        return False
    finally:
        session.close()


def main() -> int:
    """
    Main function to orchestrate download, verification, and upload
    
    Returns:
        Exit code (0 for success, 1 for failure)
    """
    
    # Get URLs from environment variables or leave empty to be prompted
    iso_url = os.environ.get('ISO_URL', '').strip()
    checksum_url = os.environ.get('CHECKSUM_URL', '').strip()
    
    # Create temporary directory for downloads
    download_dir = Path(tempfile.mkdtemp(prefix="iso_uploader_"))
    
    try:
        # Print header
        print("=" * 60)
        print("ISO Download, Verification, and Upload Tool")
        print(f"Version {__version__}")
        print("=" * 60)
        print()
        
        # Prompt for URLs if not defined
        if not iso_url:
            iso_url = input("Enter ISO download URL: ").strip()
            if not iso_url:
                print("Error: ISO URL is required")
                return 1
            
            # Validate ISO URL
            if not validate_iso_url(iso_url):
                return 1
        
        if not checksum_url:
            checksum_url = input("Enter checksum file URL: ").strip()
            if not checksum_url:
                print("Error: Checksum URL is required")
                return 1
            
            # Validate checksum URL
            if not validate_url(checksum_url, "Checksum URL"):
                return 1
            print()
        
        print(f"Using temporary directory: {download_dir}\n")
        
        # Extract filenames from URLs
        iso_filename = os.path.basename(urlparse(iso_url).path)
        checksum_filename = os.path.basename(urlparse(checksum_url).path)
        if not checksum_filename or checksum_filename == checksum_url:
            checksum_filename = "CHECKSUM"
        
        iso_path = download_dir / iso_filename
        checksum_path = download_dir / checksum_filename
        
        # Step 1: Download checksum file (small, quick)
        print("=" * 60)
        print("DOWNLOADING FILES")
        print("=" * 60)
        print()
        download_file(checksum_url, checksum_path)
        
        # Step 2: Download ISO file
        download_file(iso_url, iso_path)
        
        # Step 3: Verify checksum
        print("=" * 60)
        print("VERIFYING CHECKSUM")
        print("=" * 60)
        print()
        
        if not verify_checksum(iso_path, checksum_path):
            print("\n[FAIL] ISO verification failed. Aborting upload.")
            return 1
        
        print()
        
        # Step 4: Get credentials and upload
        cluster_url, username, password = get_credentials()
        
        if upload_to_hypercore(iso_path, cluster_url, username, password):
            return 0
        else:
            return 1
    
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        return 1
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        return 1
    finally:
        # Clean up temporary directory
        if download_dir.exists():
            print("\nCleaning up temporary files...")
            try:
                shutil.rmtree(download_dir)
                print(f"[OK] Temporary directory removed: {download_dir}")
            except OSError as e:
                print(f"Warning: Could not remove temporary directory: {e}")


if __name__ == "__main__":
    sys.exit(main())
