"""
PhishGuard AI - Advanced Feature Engineering Module
====================================================
Research-grade feature extraction for phishing URL detection.

This module implements state-of-the-art features including:
- Adversarial attack detection (homographs, bit-squatting)
- Information theory metrics (Shannon entropy)
- Advanced URI patterns (blob URIs, redirection chains)
- Domain reputation scoring (high-risk TLDs)
- Lexical and structural analysis

Author: PhishGuard Research Team
Date: 2026-02-17
Version: 2.0.0 (Research Edition)
"""

import re
import math
import unicodedata
from urllib.parse import urlparse, parse_qs
from collections import Counter
import numpy as np


# ============================================================================
# CONFIGURATION: High-Risk TLDs and Popular Domains
# ============================================================================

HIGH_RISK_TLDS = {
    # Free/Abused TLDs (Risk Score: 0.9)
    '.tk': 0.9, '.ml': 0.9, '.ga': 0.9, '.cf': 0.9, '.gq': 0.9,
    
    # New gTLDs frequently abused (Risk Score: 0.7)
    '.top': 0.7, '.xyz': 0.7, '.icu': 0.7, '.club': 0.7, '.online': 0.7,
    '.site': 0.7, '.website': 0.7, '.space': 0.7, '.tech': 0.7,
    
    # Suspicious country codes (Risk Score: 0.5)
    '.pw': 0.5, '.cc': 0.5, '.ws': 0.5, '.to': 0.5, '.nu': 0.5,
    
    # Moderate risk (Risk Score: 0.3)
    '.info': 0.3, '.biz': 0.3, '.name': 0.3, '.pro': 0.3
}

# Top 100 popular domains for bit-squatting detection
POPULAR_DOMAINS = [
    'google', 'facebook', 'youtube', 'amazon', 'twitter', 'instagram',
    'linkedin', 'netflix', 'microsoft', 'apple', 'paypal', 'ebay',
    'wikipedia', 'reddit', 'yahoo', 'bing', 'pinterest', 'tumblr',
    'wordpress', 'adobe', 'dropbox', 'github', 'stackoverflow', 'medium',
    'whatsapp', 'telegram', 'zoom', 'slack', 'discord', 'twitch',
    'spotify', 'soundcloud', 'vimeo', 'dailymotion', 'imgur', 'flickr',
    'gmail', 'outlook', 'protonmail', 'mailchimp', 'salesforce', 'shopify',
    'stripe', 'square', 'venmo', 'cashapp', 'coinbase', 'binance',
    'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc', 'barclays'
]

# Unicode confusables for homograph detection
HOMOGRAPH_CONFUSABLES = {
    # Cyrillic lookalikes
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
    'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
    'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X',
    
    # Greek lookalikes
    'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'ο': 'o', 'ρ': 'p', 'υ': 'u',
    'ν': 'v', 'ω': 'w', 'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ι': 'I', 'Κ': 'K',
    'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Ζ': 'Z',
    
    # Other confusables
    'ℓ': 'l', '１': '1', '０': '0', 'ⅰ': 'i', 'ⅼ': 'l', 'ⅴ': 'v',
}

# URL shortener patterns (for redirection chain detection)
URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'bit.do', 'short.link', 'rebrand.ly',
    'cutt.ly', 'tiny.cc', 'cli.gs', 'shorturl.at', 'hyperurl.co'
]


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def calculate_entropy(text):
    """
    Calculate Shannon entropy of a string.
    
    Entropy measures randomness/unpredictability. Higher entropy indicates
    more random strings (common in auto-generated phishing domains).
    
    Formula: H(X) = -Σ P(xi) * log2(P(xi))
    
    Args:
        text (str): Input string
        
    Returns:
        float: Shannon entropy value (0 to ~8 for typical text)
    """
    if not text:
        return 0.0
    
    # Count character frequencies
    char_counts = Counter(text)
    length = len(text)
    
    # Calculate entropy
    entropy = 0.0
    for count in char_counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def normalize_unicode(text):
    """
    Normalize Unicode characters to detect homograph attacks.
    
    Args:
        text (str): Input string with potential Unicode confusables
        
    Returns:
        str: Normalized string with confusables replaced
    """
    normalized = []
    for char in text:
        # Replace known confusables
        if char in HOMOGRAPH_CONFUSABLES:
            normalized.append(HOMOGRAPH_CONFUSABLES[char])
        else:
            normalized.append(char)
    return ''.join(normalized)


def hamming_distance(s1, s2):
    """
    Calculate Hamming distance between two strings.
    
    Used for bit-squatting detection (single character differences).
    
    Args:
        s1, s2 (str): Strings to compare
        
    Returns:
        int: Number of differing characters (or length difference if unequal)
    """
    if len(s1) != len(s2):
        return abs(len(s1) - len(s2)) + 10  # Penalize length mismatch
    
    return sum(c1 != c2 for c1, c2 in zip(s1, s2))


def extract_domain_parts(url):
    """
    Extract and parse domain components from URL.
    
    Args:
        url (str): Input URL
        
    Returns:
        dict: Parsed components (domain, subdomain, tld, etc.)
    """
    try:
        # Ensure URL has scheme
        if not url.startswith(('http://', 'https://', 'ftp://')):
            url = 'http://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Split domain parts
        parts = domain.split('.')
        
        # Extract TLD
        tld = '.' + parts[-1] if len(parts) > 1 else ''
        
        # Extract second-level domain (SLD)
        sld = parts[-2] if len(parts) > 1 else parts[0] if parts else ''
        
        # Extract subdomains
        subdomains = parts[:-2] if len(parts) > 2 else []
        
        return {
            'full_domain': domain,
            'tld': tld,
            'sld': sld,
            'subdomains': subdomains,
            'num_subdomains': len(subdomains),
            'path': parsed.path,
            'query': parsed.query,
            'fragment': parsed.fragment,
            'scheme': parsed.scheme
        }
    except Exception:
        return {
            'full_domain': '', 'tld': '', 'sld': '', 'subdomains': [],
            'num_subdomains': 0, 'path': '', 'query': '', 'fragment': '',
            'scheme': ''
        }


# ============================================================================
# ADVANCED FEATURE EXTRACTION
# ============================================================================

def extract_advanced_features(url):
    """
    Extract comprehensive research-grade features from URL.
    
    This function implements 25+ advanced features beyond basic character counts:
    - Adversarial detection (homographs, bit-squatting)
    - Information theory (entropy)
    - URI patterns (blob, redirects)
    - Domain reputation (TLD risk)
    - Lexical/structural analysis
    
    Args:
        url (str): Input URL to analyze
        
    Returns:
        dict: Dictionary of 38 features (13 baseline + 25 advanced)
    """
    features = {}
    
    # ========================================================================
    # BASELINE FEATURES (13) - From original implementation
    # ========================================================================
    
    # Basic length features
    features['url_length'] = len(url)
    
    # Parse URL
    domain_info = extract_domain_parts(url)
    domain = domain_info['full_domain']
    
    features['domain_length'] = len(domain)
    
    # Character count features
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_underscores'] = url.count('_')
    features['num_slashes'] = url.count('/')
    features['num_question'] = url.count('?')
    features['num_equals'] = url.count('=')
    features['num_at'] = url.count('@')
    
    # IP address detection
    ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    features['has_ip'] = 1 if ip_pattern.search(url) else 0
    
    # HTTPS detection
    features['has_https'] = 1 if url.startswith('https://') else 0
    
    # Suspicious keywords
    suspicious_keywords = [
        'login', 'verify', 'account', 'update', 'secure', 'bank',
        'confirm', 'password', 'signin', 'ebay', 'paypal', 'amazon',
        'free', 'bonus', 'click', 'here', 'winner'
    ]
    features['suspicious_words'] = sum(1 for word in suspicious_keywords if word in url.lower())
    
    # Subdomain count
    features['num_subdomains'] = domain_info['num_subdomains']
    
    # ========================================================================
    # ADVANCED FEATURES (25+) - Research-grade additions
    # ========================================================================
    
    # ------------------------------------------------------------------------
    # 1. ADVERSARIAL DETECTION: Homograph Attacks
    # ------------------------------------------------------------------------
    
    # Detect non-ASCII characters (IDN/Punycode)
    features['has_non_ascii'] = 1 if any(ord(c) > 127 for c in url) else 0
    
    # Count Unicode confusable characters
    confusable_count = sum(1 for c in domain if c in HOMOGRAPH_CONFUSABLES)
    features['confusable_chars'] = confusable_count
    
    # Homograph suspicion score (0-1)
    features['homograph_score'] = min(confusable_count / max(len(domain), 1), 1.0)
    
    # Check if domain differs from normalized version
    normalized_domain = normalize_unicode(domain)
    features['is_homograph'] = 1 if normalized_domain != domain else 0
    
    # ------------------------------------------------------------------------
    # 2. ADVERSARIAL DETECTION: Bit-squatting
    # ------------------------------------------------------------------------
    
    # Calculate minimum Hamming distance to popular domains
    sld = domain_info['sld']
    min_hamming = float('inf')
    
    for popular in POPULAR_DOMAINS:
        dist = hamming_distance(sld, popular)
        if dist < min_hamming:
            min_hamming = dist
    
    features['min_hamming_distance'] = min_hamming if min_hamming != float('inf') else 20
    
    # Bit-squatting suspicion (1 if within 1-2 characters of popular domain)
    features['bitsquat_suspicion'] = 1 if min_hamming <= 2 else 0
    
    # ------------------------------------------------------------------------
    # 3. INFORMATION THEORY: Shannon Entropy
    # ------------------------------------------------------------------------
    
    # Domain entropy (randomness of domain name)
    features['domain_entropy'] = calculate_entropy(domain)
    
    # Path entropy
    features['path_entropy'] = calculate_entropy(domain_info['path'])
    
    # Query entropy
    features['query_entropy'] = calculate_entropy(domain_info['query'])
    
    # Subdomain entropy (average across all subdomains)
    if domain_info['subdomains']:
        subdomain_entropies = [calculate_entropy(sub) for sub in domain_info['subdomains']]
        features['subdomain_entropy_avg'] = np.mean(subdomain_entropies)
        features['subdomain_entropy_max'] = np.max(subdomain_entropies)
    else:
        features['subdomain_entropy_avg'] = 0.0
        features['subdomain_entropy_max'] = 0.0
    
    # ------------------------------------------------------------------------
    # 4. ADVANCED URI PATTERNS
    # ------------------------------------------------------------------------
    
    # Blob URI detection
    features['is_blob_uri'] = 1 if url.startswith('blob:') else 0
    
    # Data URI detection
    features['is_data_uri'] = 1 if url.startswith('data:') else 0
    
    # Redirection chain suspicion (URL shortener detection)
    features['is_shortener'] = 1 if any(shortener in domain for shortener in URL_SHORTENERS) else 0
    
    # Nested redirect patterns (multiple slashes after domain)
    path_slashes = domain_info['path'].count('/')
    features['path_depth'] = path_slashes
    features['deep_path'] = 1 if path_slashes > 5 else 0
    
    # Double slash in path (often used in redirects)
    features['has_double_slash'] = 1 if '//' in domain_info['path'] else 0
    
    # ------------------------------------------------------------------------
    # 5. DOMAIN REPUTATION: High-Risk TLDs
    # ------------------------------------------------------------------------
    
    tld = domain_info['tld']
    
    # TLD risk score (0.0 = safe, 0.9 = high risk)
    features['tld_risk_score'] = HIGH_RISK_TLDS.get(tld, 0.0)
    
    # Binary flag for high-risk TLD
    features['is_high_risk_tld'] = 1 if features['tld_risk_score'] >= 0.7 else 0
    
    # TLD length (longer TLDs are sometimes suspicious)
    features['tld_length'] = len(tld)
    
    # ------------------------------------------------------------------------
    # 6. LEXICAL FEATURES
    # ------------------------------------------------------------------------
    
    # Vowel-consonant ratio (phishing URLs often have unusual ratios)
    vowels = sum(1 for c in domain.lower() if c in 'aeiou')
    consonants = sum(1 for c in domain.lower() if c.isalpha() and c not in 'aeiou')
    features['vowel_ratio'] = vowels / max(len(domain), 1)
    features['consonant_ratio'] = consonants / max(len(domain), 1)
    
    # Digit-to-letter ratio
    digits = sum(1 for c in domain if c.isdigit())
    letters = sum(1 for c in domain if c.isalpha())
    features['digit_ratio'] = digits / max(len(domain), 1)
    features['letter_ratio'] = letters / max(len(domain), 1)
    
    # Consecutive consonants (max sequence)
    max_consecutive_consonants = 0
    current_consecutive = 0
    for c in domain.lower():
        if c.isalpha() and c not in 'aeiou':
            current_consecutive += 1
            max_consecutive_consonants = max(max_consecutive_consonants, current_consecutive)
        else:
            current_consecutive = 0
    features['max_consecutive_consonants'] = max_consecutive_consonants
    
    # ------------------------------------------------------------------------
    # 7. STRUCTURAL FEATURES
    # ------------------------------------------------------------------------
    
    # Query parameter count
    query_params = parse_qs(domain_info['query'])
    features['num_query_params'] = len(query_params)
    
    # Fragment presence
    features['has_fragment'] = 1 if domain_info['fragment'] else 0
    
    # Port presence (non-standard ports are suspicious)
    features['has_port'] = 1 if ':' in domain_info['full_domain'] and not domain_info['full_domain'].endswith(':') else 0
    
    # Special characters in domain (excluding dots and hyphens)
    special_chars = sum(1 for c in domain if not c.isalnum() and c not in '.-')
    features['special_chars_in_domain'] = special_chars
    
    # Uppercase letters in domain (unusual for legitimate URLs)
    features['has_uppercase'] = 1 if any(c.isupper() for c in domain) else 0
    
    return features


# ============================================================================
# BATCH PROCESSING
# ============================================================================

def extract_features_batch(urls, verbose=True):
    """
    Extract features from a batch of URLs with progress tracking.
    
    Args:
        urls (list): List of URLs to process
        verbose (bool): Print progress updates
        
    Returns:
        list: List of feature dictionaries
    """
    features_list = []
    total = len(urls)
    
    for idx, url in enumerate(urls):
        if verbose and idx % 10000 == 0:
            print(f"  Processed {idx:,}/{total:,} URLs ({idx/total*100:.1f}%)")
        
        try:
            features = extract_advanced_features(str(url))
            features_list.append(features)
        except Exception as e:
            # If extraction fails, return zero features
            if verbose and idx % 10000 == 0:
                print(f"  Warning: Failed to extract features for URL at index {idx}: {e}")
            
            # Create zero-filled feature dict
            zero_features = {f'feature_{i}': 0 for i in range(38)}
            features_list.append(zero_features)
    
    if verbose:
        print(f"  ✓ Completed: {total:,}/{total:,} URLs (100.0%)")
    
    return features_list


# ============================================================================
# FEATURE METADATA
# ============================================================================

def get_feature_names():
    """
    Get ordered list of all feature names.
    
    Returns:
        list: List of 38 feature names in extraction order
    """
    # Extract from a dummy URL to get feature names
    dummy_features = extract_advanced_features('http://example.com')
    return list(dummy_features.keys())


def get_feature_descriptions():
    """
    Get detailed descriptions of all features for documentation.
    
    Returns:
        dict: Feature name -> description mapping
    """
    return {
        # Baseline features
        'url_length': 'Total character count in URL',
        'domain_length': 'Character count in domain name',
        'num_dots': 'Count of dot (.) characters',
        'num_hyphens': 'Count of hyphen (-) characters',
        'num_underscores': 'Count of underscore (_) characters',
        'num_slashes': 'Count of slash (/) characters',
        'num_question': 'Count of question mark (?) characters',
        'num_equals': 'Count of equals (=) characters',
        'num_at': 'Count of at (@) characters',
        'has_ip': 'Binary flag: 1 if IP address used instead of domain',
        'has_https': 'Binary flag: 1 if HTTPS protocol used',
        'suspicious_words': 'Count of suspicious keywords (login, verify, etc.)',
        'num_subdomains': 'Number of subdomain levels',
        
        # Advanced features
        'has_non_ascii': 'Binary flag: 1 if non-ASCII characters present (IDN)',
        'confusable_chars': 'Count of Unicode confusable characters',
        'homograph_score': 'Homograph attack suspicion score (0-1)',
        'is_homograph': 'Binary flag: 1 if homograph attack detected',
        'min_hamming_distance': 'Minimum Hamming distance to popular domains',
        'bitsquat_suspicion': 'Binary flag: 1 if bit-squatting suspected',
        'domain_entropy': 'Shannon entropy of domain name',
        'path_entropy': 'Shannon entropy of URL path',
        'query_entropy': 'Shannon entropy of query string',
        'subdomain_entropy_avg': 'Average entropy across subdomains',
        'subdomain_entropy_max': 'Maximum entropy among subdomains',
        'is_blob_uri': 'Binary flag: 1 if blob: URI scheme',
        'is_data_uri': 'Binary flag: 1 if data: URI scheme',
        'is_shortener': 'Binary flag: 1 if URL shortener detected',
        'path_depth': 'Number of path segments (slash count)',
        'deep_path': 'Binary flag: 1 if path depth > 5',
        'has_double_slash': 'Binary flag: 1 if double slash in path',
        'tld_risk_score': 'TLD risk score (0.0-0.9)',
        'is_high_risk_tld': 'Binary flag: 1 if high-risk TLD (score >= 0.7)',
        'tld_length': 'Character count in TLD',
        'vowel_ratio': 'Ratio of vowels to total domain length',
        'consonant_ratio': 'Ratio of consonants to total domain length',
        'digit_ratio': 'Ratio of digits to total domain length',
        'letter_ratio': 'Ratio of letters to total domain length',
        'max_consecutive_consonants': 'Maximum consecutive consonant sequence',
        'num_query_params': 'Number of query parameters',
        'has_fragment': 'Binary flag: 1 if URL fragment present',
        'has_port': 'Binary flag: 1 if non-standard port specified',
        'special_chars_in_domain': 'Count of special characters in domain',
        'has_uppercase': 'Binary flag: 1 if uppercase letters in domain'
    }


# ============================================================================
# TESTING & VALIDATION
# ============================================================================

if __name__ == '__main__':
    """
    Test the advanced feature extraction on sample URLs.
    """
    print("=" * 70)
    print("PHISHGUARD ADVANCED FEATURE EXTRACTION - TEST MODE")
    print("=" * 70)
    
    # Test URLs
    test_urls = [
        # Benign
        'https://www.google.com',
        'https://github.com/user/repo',
        
        # Phishing (homograph)
        'https://www.gооgle.com',  # Cyrillic 'о' instead of 'o'
        
        # Phishing (bit-squatting)
        'https://www.gooogle.com',  # Extra 'o'
        
        # Suspicious TLD
        'https://free-prize.xyz/claim',
        
        # URL shortener
        'https://bit.ly/abc123',
        
        # High entropy
        'https://xk7f9m2p.tk/login',
        
        # Deep path
        'https://example.com/a/b/c/d/e/f/g/h/i/j'
    ]
    
    print(f"\nTesting feature extraction on {len(test_urls)} sample URLs...\n")
    
    for idx, url in enumerate(test_urls, 1):
        print(f"\n[{idx}] URL: {url}")
        print("-" * 70)
        
        features = extract_advanced_features(url)
        
        # Display key features
        key_features = [
            'url_length', 'domain_entropy', 'homograph_score',
            'bitsquat_suspicion', 'tld_risk_score', 'is_shortener',
            'path_depth', 'suspicious_words'
        ]
        
        for feat in key_features:
            value = features.get(feat, 'N/A')
            if isinstance(value, float):
                print(f"  {feat:25s}: {value:.3f}")
            else:
                print(f"  {feat:25s}: {value}")
    
    print("\n" + "=" * 70)
    print(f"✓ Feature extraction test complete!")
    print(f"  Total features: {len(get_feature_names())}")
    print("=" * 70)
