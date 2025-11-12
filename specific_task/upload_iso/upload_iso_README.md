# Hypercore ISO Uploader

A Python script to download ISO images, verify their checksums, and upload them to Scale Computing Hypercore via the REST API.

## Features

- **Download**: Fetch ISOs from any HTTP/HTTPS URL with progress tracking
- **Verify**: SHA256 checksum verification with support for multiple checksum file formats
- **Upload**: Three-step upload process to Hypercore with detailed progress reporting
- **Cleanup**: Automatic removal of temporary files after completion
- **Flexible**: Supports environment variables or interactive prompts

## Requirements

- Python 3.6 or higher
- `requests` library
- Scale Computing Hypercore cluster with REST API access

## Installation

```bash
pip install requests
```

For production use, consider using a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
pip install requests
```

## Usage

### Interactive Mode

Run the script and follow the prompts:

```bash
python3 upload_iso.py
```

You'll be prompted for:
1. ISO download URL
2. Checksum file URL
3. Hypercore cluster IP/hostname
4. Username and password

### Environment Variables

Set any combination of these to avoid repeated prompts:

```bash
# Credentials
export SC_HOST="192.168.1.100"
export SC_USERNAME="admin"
export SC_PASSWORD="your-password"

# ISO URLs (optional - useful for automation)
export ISO_URL="https://repo.almalinux.org/almalinux/10.0/isos/x86_64/AlmaLinux-10.0-x86_64-boot.iso"
export CHECKSUM_URL="https://repo.almalinux.org/almalinux/10.0/isos/x86_64/CHECKSUM"

python3 upload_iso.py
```

Any missing variables will trigger an interactive prompt.

## Example Output

```
============================================================
ISO Download, Verification, and Upload Tool
Version 1.1.0
============================================================

Enter ISO download URL: https://repo.almalinux.org/almalinux/10.0/isos/x86_64/AlmaLinux-10.0-x86_64-boot.iso
Enter checksum file URL: https://repo.almalinux.org/almalinux/10.0/isos/x86_64/CHECKSUM

Using temporary directory: /tmp/iso_uploader_xyz123

============================================================
DOWNLOADING FILES
============================================================

Downloading: https://repo.almalinux.org/almalinux/10.0/isos/x86_64/CHECKSUM
Download complete (size unknown)

Downloading: https://repo.almalinux.org/almalinux/10.0/isos/x86_64/AlmaLinux-10.0-x86_64-boot.iso
File size: 815.7 MB
[========================================] 100.0% (815.7 MB/815.7 MB)

============================================================
VERIFYING CHECKSUM
============================================================

Parsing checksum file: CHECKSUM
Found checksum for AlmaLinux-10.0-x86_64-boot.iso: abc123...

Calculating SHA256 checksum for AlmaLinux-10.0-x86_64-boot.iso...
Hashing: [========================================] 100.0% (815.7 MB/815.7 MB)
Calculated checksum: abc123...

[PASS] Checksum verification successful

============================================================
UPLOADING TO HYPERCORE
============================================================

WARNING: SSL certificate verification is DISABLED
         Ensure you are on a trusted network

Step 1: Creating ISO record for 'AlmaLinux-10.0-x86_64-boot.iso'...
[OK] ISO record created with UUID: 12345678-1234-1234-1234-123456789abc

Step 2: Uploading ISO data (815.7 MB)...
Uploading: [========================================] 100.0% (815.7 MB/815.7 MB)
[OK] ISO data uploaded successfully

Step 3: Marking ISO as ready for insert...
[OK] ISO marked as ready for insert

============================================================
SUCCESS: ISO 'AlmaLinux-10.0-x86_64-boot.iso' uploaded to Hypercore
         UUID: 12345678-1234-1234-1234-123456789abc
============================================================

Cleaning up temporary files...
[OK] Temporary directory removed: /tmp/iso_uploader_xyz123
```

## Supported Checksum Formats

The script automatically detects these formats:

- **BSD-style**: `SHA256 (filename.iso) = abc123...`
- **GNU-style**: `abc123... filename.iso`
- **With asterisk**: `abc123... *filename.iso`

## Security Warning

This script **disables SSL certificate verification** to support self-signed certificates commonly used by Hypercore clusters.

- ✅ **Safe**: On isolated internal networks (LAN)
- ❌ **Unsafe**: Over public networks or the internet

Only use this tool on trusted networks.

## Troubleshooting

| Error | Solution |
|-------|----------|
| Checksum verification failed | Re-download the ISO or verify you have the correct checksum file |
| HTTP 401 Unauthorized | Check username and password |
| HTTP 403 Forbidden | Verify user has ISO upload permissions in Hypercore |
| HTTP 500 Server Error | Ensure filename ends with `.iso` and Hypercore has sufficient storage |
| Download/upload timeout | Check network connectivity; large files may take 10+ minutes |

For detailed error messages, check the script output.
