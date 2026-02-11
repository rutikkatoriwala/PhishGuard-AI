"""
PhishGuard AI - Data Cleaning Script
This script cleans the malicious_phish.csv dataset by:
1. Removing duplicates
2. Handling missing values
3. Standardizing class labels
4. Validating URL format
5. Removing whitespace and special characters
6. Creating a cleaned version of the dataset
"""

import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse

print("="*70)
print("PHISHGUARD AI - DATA CLEANING PIPELINE")
print("="*70)

# Load the dataset
print("\n[1/8] Loading dataset...")
try:
    df = pd.read_csv('malicious_phish.csv')
    print(f"✓ Loaded {len(df):,} rows with {len(df.columns)} columns")
    print(f"  Columns: {df.columns.tolist()}")
except Exception as e:
    print(f"✗ Error loading CSV: {e}")
    exit(1)

# Store original count
original_count = len(df)

# Display initial info
print(f"\n[2/8] Initial Data Analysis...")
print(f"  Shape: {df.shape}")
print(f"  Memory usage: {df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
if 'type' in df.columns:
    print(f"  Class distribution:\n{df['type'].value_counts()}")

# Check for missing values
print(f"\n[3/8] Checking for missing values...")
missing = df.isnull().sum()
if missing.sum() > 0:
    print(f"  Missing values found:")
    for col in missing[missing > 0].index:
        print(f"    - {col}: {missing[col]:,} ({(missing[col]/len(df)*100):.2f}%)")
    
    # Drop rows with missing values
    df = df.dropna()
    print(f"  ✓ Dropped {original_count - len(df):,} rows with missing values")
    print(f"  Remaining rows: {len(df):,}")
else:
    print(f"  ✓ No missing values found")

# Remove duplicates
print(f"\n[4/8] Removing duplicate rows...")
duplicates_before = df.duplicated().sum()
if duplicates_before > 0:
    df = df.drop_duplicates()
    print(f"  ✓ Removed {duplicates_before:,} duplicate rows ({(duplicates_before/original_count*100):.2f}%)")
    print(f"  Remaining rows: {len(df):,}")
else:
    print(f"  ✓ No duplicate rows found")

# Clean URL column
if 'url' in df.columns:
    print(f"\n[5/8] Cleaning URL column...")
    
    # Remove leading/trailing whitespace
    df['url'] = df['url'].astype(str).str.strip()
    
    # Remove URLs with internal whitespace
    whitespace_urls = df['url'].str.contains(r'\s').sum()
    if whitespace_urls > 0:
        df = df[~df['url'].str.contains(r'\s')]
        print(f"  ✓ Removed {whitespace_urls:,} URLs containing whitespace")
    
    # Remove empty URLs
    empty_urls = (df['url'] == '').sum() + (df['url'] == 'nan').sum()
    if empty_urls > 0:
        df = df[(df['url'] != '') & (df['url'] != 'nan')]
        print(f"  ✓ Removed {empty_urls:,} empty URLs")
    
    # Remove duplicate URLs (keep first occurrence)
    url_duplicates = df['url'].duplicated().sum()
    if url_duplicates > 0:
        df = df.drop_duplicates(subset=['url'], keep='first')
        print(f"  ✓ Removed {url_duplicates:,} duplicate URLs")
    
    # Validate URL format (basic check)
    def is_valid_url(url):
        try:
            # Check if URL has at least a dot and some characters
            if '.' not in url:
                return False
            # Check for minimum length
            if len(url) < 4:
                return False
            # Check for suspicious patterns
            if url.count('.') > 10:  # Too many dots
                return False
            return True
        except:
            return False
    
    invalid_urls = ~df['url'].apply(is_valid_url)
    invalid_count = invalid_urls.sum()
    if invalid_count > 0:
        df = df[~invalid_urls]
        print(f"  ✓ Removed {invalid_count:,} invalid URLs")
    
    print(f"  Remaining rows: {len(df):,}")
else:
    print(f"\n[5/8] URL column not found - skipping URL cleaning")

# Standardize class labels
if 'type' in df.columns:
    print(f"\n[6/8] Standardizing class labels...")
    
    # Convert to lowercase and strip whitespace
    df['type'] = df['type'].astype(str).str.lower().str.strip()
    
    # Show unique values
    unique_types = df['type'].unique()
    print(f"  Unique class labels: {unique_types}")
    
    # Standardize common variations
    label_mapping = {
        'phishing': 'phishing',
        'phish': 'phishing',
        'malware': 'malware',
        'malicious': 'malware',
        'benign': 'benign',
        'legitimate': 'benign',
        'safe': 'benign',
        'defacement': 'defacement',
        'defaced': 'defacement'
    }
    
    # Apply mapping
    df['type'] = df['type'].map(lambda x: label_mapping.get(x, x))
    
    # Remove any rows with unknown labels
    valid_labels = ['benign', 'phishing', 'malware', 'defacement']
    unknown_labels = ~df['type'].isin(valid_labels)
    unknown_count = unknown_labels.sum()
    if unknown_count > 0:
        print(f"  ✓ Removed {unknown_count:,} rows with unknown labels")
        df = df[~unknown_labels]
    
    print(f"  Final class distribution:")
    print(df['type'].value_counts())
    print(f"  Remaining rows: {len(df):,}")
else:
    print(f"\n[6/8] Type column not found - skipping label standardization")

# Remove outliers (URLs that are too short or too long)
if 'url' in df.columns:
    print(f"\n[7/8] Removing outliers...")
    
    # Calculate URL lengths
    df['url_length'] = df['url'].str.len()
    
    # Define reasonable bounds
    min_length = 4  # Minimum URL length (e.g., "a.co")
    max_length = 2000  # Maximum URL length
    
    outliers = (df['url_length'] < min_length) | (df['url_length'] > max_length)
    outlier_count = outliers.sum()
    
    if outlier_count > 0:
        df = df[~outliers]
        print(f"  ✓ Removed {outlier_count:,} URLs with abnormal length (< {min_length} or > {max_length} chars)")
    
    # Drop the temporary column
    df = df.drop('url_length', axis=1)
    
    print(f"  Remaining rows: {len(df):,}")
else:
    print(f"\n[7/8] URL column not found - skipping outlier removal")

# Reset index
df = df.reset_index(drop=True)

# Save cleaned dataset
print(f"\n[8/8] Saving cleaned dataset...")
output_file = 'malicious_phish_cleaned.csv'
df.to_csv(output_file, index=False)
print(f"  ✓ Saved to '{output_file}'")

# Final summary
print("\n" + "="*70)
print("CLEANING SUMMARY")
print("="*70)
print(f"Original rows:    {original_count:,}")
print(f"Cleaned rows:     {len(df):,}")
print(f"Rows removed:     {original_count - len(df):,} ({((original_count - len(df))/original_count*100):.2f}%)")
print(f"Final columns:    {len(df.columns)}")
print(f"File size:        {df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")

if 'type' in df.columns:
    print(f"\nFinal class distribution:")
    for label, count in df['type'].value_counts().items():
        percentage = (count / len(df)) * 100
        print(f"  {label:15s}: {count:8,} ({percentage:5.2f}%)")

print("\n" + "="*70)
print("✓ DATA CLEANING COMPLETE!")
print("="*70)
print(f"\nNext steps:")
print(f"1. Review the cleaned dataset: {output_file}")
print(f"2. Update train_model.py to use the cleaned dataset")
print(f"3. Retrain the model with: python train_model.py")
print(f"4. Test the application with: python app.py")
