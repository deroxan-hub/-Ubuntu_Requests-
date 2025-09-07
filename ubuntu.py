#!/usr/bin/env python3
"""
Enhanced Image Fetcher - A Python script to safely download multiple images from URLs
with security precautions and duplicate prevention.
"""

import os
import requests
from urllib.parse import urlparse, unquote
from pathlib import Path
import mimetypes
from datetime import datetime
import hashlib
import re
import magic  # python-magic or python-magic-bin on Windows

def create_directory(directory_name):
    """Create directory if it doesn't exist"""
    try:
        os.makedirs(directory_name, exist_ok=True)
        print(f"✓ Directory '{directory_name}' is ready")
        return True
    except OSError as e:
        print(f"✗ Error creating directory: {e}")
        return False

def extract_filename_from_url(url):
    """Extract filename from URL or generate one if not available"""
    parsed_url = urlparse(url)
    path = unquote(parsed_url.path)  # Handle URL encoded characters
    
    # Extract filename from path
    if path and '/' in path:
        filename = path.split('/')[-1]
        # Remove any query parameters from filename
        if '?' in filename:
            filename = filename.split('?')[0]
        if filename and '.' in filename:
            # Sanitize filename to remove potentially dangerous characters
            filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
            return filename
    
    # If no proper filename found, generate one with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"image_{timestamp}.jpg"

def is_valid_image_url(url):
    """Check if the URL might point to an image"""
    image_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.tiff', '.svg']
    parsed_url = urlparse(url)
    path = parsed_url.path.lower()
    return any(path.endswith(ext) for ext in image_extensions)

def validate_url(url):
    """Validate URL format and safety"""
    if not url:
        return False, "Empty URL provided"
    
    # Check URL format
    if not url.startswith(('http://', 'https://')):
        return False, "Invalid URL format. Please use http:// or https://"
    
    # Parse URL to check for suspicious patterns
    parsed_url = urlparse(url)
    
    # Check for localhost or private IP addresses
    hostname = parsed_url.hostname
    if hostname in ['localhost', '127.0.0.1', '0.0.0.0']:
        return False, "URL points to localhost which is not allowed"
    
    # Check for private IP ranges
    if hostname and re.match(r'^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)', hostname):
        return False, "URL points to private IP range which is not allowed"
    
    # Check for potentially malicious file extensions
    malicious_extensions = ['.exe', '.bat', '.cmd', '.sh', '.php', '.js', '.html']
    path = parsed_url.path.lower()
    if any(path.endswith(ext) for ext in malicious_extensions):
        return False, "URL points to potentially dangerous file type"
    
    return True, "URL appears valid"

def calculate_file_hash(content):
    """Calculate SHA-256 hash of file content for duplicate detection"""
    return hashlib.sha256(content).hexdigest()

def check_duplicate_image(content, save_directory):
    """Check if image with same content already exists"""
    content_hash = calculate_file_hash(content)
    
    # Check all files in directory for matching hash
    for filename in os.listdir(save_directory):
        filepath = os.path.join(save_directory, filename)
        if os.path.isfile(filepath):
            try:
                with open(filepath, 'rb') as f:
                    existing_hash = calculate_file_hash(f.read())
                    if existing_hash == content_hash:
                        return True, filename
            except IOError:
                continue
    
    return False, content_hash

def check_http_headers(response):
    """Check HTTP headers for security considerations"""
    headers = response.headers
    issues = []
    
    # Check content type
    content_type = headers.get('content-type', '')
    if not content_type.startswith('image/'):
        issues.append(f"Content-Type is not an image: {content_type}")
    
    # Check content length
    content_length = headers.get('content-length')
    if content_length:
        size_mb = int(content_length) / (1024 * 1024)
        if size_mb > 10:  # Warn for files larger than 10MB
            issues.append(f"Large file size: {size_mb:.2f} MB")
    
    # Check for security headers
    security_headers = ['x-content-type-options', 'x-frame-options', 'x-xss-protection']
    for header in security_headers:
        if header not in headers:
            issues.append(f"Missing security header: {header}")
    
    return issues

def download_image(url, save_directory, max_size_mb=20):
    """Download image from URL with security precautions"""
    try:
        # Validate URL
        is_valid, message = validate_url(url)
        if not is_valid:
            print(f"✗ {message}")
            return False
        
        # Check if URL might be an image
        if not is_valid_image_url(url):
            print("⚠ Warning: The URL doesn't appear to point to a common image format")
            confirm = input("Do you want to proceed anyway? (y/N): ").strip().lower()
            if confirm != 'y':
                print("Download cancelled by user")
                return False
        
        # Send HEAD request first to check headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0'
        }
        
        print(f"🔍 Pre-flight check for {urlparse(url).netloc}...")
        try:
            head_response = requests.head(url, headers=headers, timeout=15, allow_redirects=True)
            header_issues = check_http_headers(head_response)
            
            if header_issues:
                print("⚠ Header warnings:")
                for issue in header_issues:
                    print(f"  - {issue}")
                confirm = input("Do you want to proceed? (y/N): ").strip().lower()
                if confirm != 'y':
                    print("Download cancelled due to header issues")
                    return False
        except requests.exceptions.RequestException:
            print("⚠ Could not perform pre-flight header check, proceeding anyway...")
        
        # Send GET request with size limits
        print(f"🌐 Downloading from {urlparse(url).netloc}...")
        response = requests.get(
            url, 
            headers=headers, 
            timeout=30, 
            stream=True,  # Stream response to handle large files
            allow_redirects=True
        )
        
        # Check for HTTP errors
        response.raise_for_status()
        
        # Check content size
        content_length = response.headers.get('content-length')
        if content_length:
            size_mb = int(content_length) / (1024 * 1024)
            if size_mb > max_size_mb:
                print(f"✗ File too large ({size_mb:.2f} MB). Max allowed: {max_size_mb} MB")
                return False
        
        # Read content in chunks to handle large files
        content = b''
        for chunk in response.iter_content(chunk_size=8192):
            content += chunk
            # Check if we've exceeded the size limit during download
            if len(content) > max_size_mb * 1024 * 1024:
                print(f"✗ File exceeded size limit during download ({max_size_mb} MB)")
                return False
        
        # Check for duplicates
        is_duplicate, duplicate_info = check_duplicate_image(content, save_directory)
        if is_duplicate:
            print(f"⏭️  Skipping duplicate image (already exists as: {duplicate_info})")
            return True  # Consider this a "success" but didn't download
        
        # Verify it's actually an image using magic numbers
        try:
            file_type = magic.from_buffer(content, mime=True)
            if not file_type.startswith('image/'):
                print(f"✗ Downloaded content is not an image (detected: {file_type})")
                return False
        except (ImportError, AttributeError):
            # Fallback if magic library is not available
            content_type = response.headers.get('content-type', '')
            if not content_type.startswith('image/'):
                print(f"⚠ Could not verify file type with magic, relying on Content-Type: {content_type}")
        
        # Determine filename
        filename = extract_filename_from_url(url)
        filepath = os.path.join(save_directory, filename)
        
        # Ensure unique filename if file already exists
        counter = 1
        base_name, extension = os.path.splitext(filename)
        while os.path.exists(filepath):
            filename = f"{base_name}_{counter}{extension}"
            filepath = os.path.join(save_directory, filename)
            counter += 1
        
        # Save the image
        with open(filepath, 'wb') as file:
            file.write(content)
        
        file_size = len(content) / 1024  # Convert to KB
        print(f"✓ Successfully downloaded: {filename}")
        print(f"📁 Saved to: {filepath}")
        print(f"📊 File size: {file_size:.2f} KB")
        print(f"🔐 Content hash: {calculate_file_hash(content)}")
        
        return True
        
    except requests.exceptions.RequestException as e:
        print(f"✗ Network error: {e}")
        return False
    except IOError as e:
        print(f"✗ File system error: {e}")
        return False
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return False

def get_urls_from_user():
    """Get multiple URLs from user input"""
    print("Enter image URLs (one per line). Press Enter twice to finish:")
    urls = []
    while True:
        try:
            line = input().strip()
            if not line:
                if urls:
                    break
                else:
                    print("Please enter at least one URL or press Ctrl+C to cancel")
                    continue
            urls.append(line)
        except EOFError:
            break
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
            return []
    
    return urls

def main():
    """Main function to run the image fetcher"""
    print("=" * 60)
    print("🖼️  Enhanced Image Fetcher - Ubuntu Community Tool")
    print("=" * 60)
    print("This tool helps you safely download multiple images from the web")
    print("with security precautions and duplicate prevention.")
    print("=" * 60)
    
    # Create directory for images
    directory_name = "Fetched_Images"
    if not create_directory(directory_name):
        return
    
    # Get URLs from user
    try:
        urls = get_urls_from_user()
        
        if not urls:
            print("✗ No URLs provided. Exiting.")
            return
        
        print(f"\n📋 Processing {len(urls)} URLs...")
        
        # Download each image
        success_count = 0
        for i, url in enumerate(urls, 1):
            print(f"\n[{i}/{len(urls)}] Processing: {url}")
            if download_image(url, directory_name):
                success_count += 1
        
        # Print summary
        print("\n" + "=" * 40)
        print("📊 Download Summary:")
        print(f"Total URLs processed: {len(urls)}")
        print(f"Successful downloads: {success_count}")
        print(f"Failed downloads: {len(urls) - success_count}")
        print("=" * 40)
        
        if success_count > 0:
            print("🎉 Some downloads completed successfully!")
            print("💾 Your images are ready for sharing in the community!")
        else:
            print("❌ All downloads failed. Please check the URLs and try again.")
            
    except KeyboardInterrupt:
        print("\n\n👋 Operation cancelled by user. Stay Ubuntu!")
    except EOFError:
        print("\n\n👋 Goodbye! Keep sharing with the community!")

if __name__ == "__main__":
    main()