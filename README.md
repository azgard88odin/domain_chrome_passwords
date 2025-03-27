# Chrome Password Decryption for Active Directory Domains

## Overview
This script allows you to decrypt and extract saved passwords from Google Chrome browser profiles. It's particularly useful in Active Directory environments where administrative users can retrieve passwords from other user profiles through impersonation.

## Credits
- Original script created by **LimerBoy**
- Inspiration from **John Hammond's** YouTube channel
- Modified for Active Directory domain environments

## Dependencies
To run this script, you'll need to install the following Python packages:

```
pip install pywin32
pip install pycryptodomex
```

- **pywin32**: Provides access to Windows APIs for user impersonation and cryptography
- **pycryptodomex**: Used for AES decryption of the Chrome passwords

## Features
- Decrypts passwords from Chrome's encrypted storage
- Supports user impersonation in domain environments
- Exports results to CSV format for easy analysis
- Works with multiple Chrome profiles

## Usage

### Basic Usage (Current User)
```
python3 decrypt_chrome_passwords_domain.py
```

### Impersonation Mode (Another User)
```
python3 decrypt_chrome_passwords_domain.py USERNAME
```

**NOTE:** When using impersonation mode, you will be prompted for the target user's password. Administrative privileges are required for successful impersonation.

## How It Works
1. The script locates Chrome's encrypted storage files
2. Extracts the encryption keys from Chrome's Local State
3. Decrypts saved login credentials
4. Outputs the results to console and a CSV file

## Use Case
This tool was developed in an Active Directory domain environment while playing around as an admin user. With a user's credentials, you can extract their Chrome passwords by impersonating them from your current profile.

## Security Notice
This tool should only be used for legitimate security purposes by authorized personnel. Unauthorized access to user credentials is illegal and unethical.
