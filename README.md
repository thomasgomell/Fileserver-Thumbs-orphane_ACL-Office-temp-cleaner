# Unwanted Files Cleanup Tool

A Go application that helps maintain Windows file systems by performing three main tasks:
1. Removing unwanted temporary files and thumbnails
2. Cleaning orphaned ACL entries
3. Replacing orphaned NTFS owners

## Features

- **Cleanup of Unwanted Files**
  - Removes common temporary files like:
    - Thumbs.db
    - Office temporary files (~$*.docx, ~$*.xlsx, etc.)
    - General temporary files (~*.tmp)
  - Parallel processing for better performance
  - Detailed logging of all operations

- **ACL Management**
  - Detects and removes invalid ACL entries
  - Cleans up orphaned Security Identifiers (SIDs)
  - Maintains valid ACL entries

- **NTFS Owner Management**
  - Identifies files with orphaned owners
  - Replaces invalid owners with specified valid user
  - Preserves existing valid ownership information

## Requirements

- Go 1.23.0 or higher
- Windows operating system
- Administrative privileges

## Dependencies

- github.com/hectane/go-acl
- golang.org/x/sys

## Installation

```sh
git clone [repository-url]
cd [repository-name]
go mod download
go build