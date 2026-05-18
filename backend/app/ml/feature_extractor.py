# -*- coding: utf-8 -*-
"""
URLFeatureExtractor - Standalone Class
======================================

This file contains the URLFeatureExtractor class.
Backend person MUST import this before loading the pickle file!

HOW TO USE:
-----------
1. Save this as: feature_extractor.py
2. In your FastAPI code, add:
   from feature_extractor import URLFeatureExtractor
3. Then load pickle:
   model_package = joblib.load('phishing_detector_enhanced.pkl')
4. It will work! ✓
"""

import numpy as np
from urllib.parse import urlparse, parse_qs
import re
import string


class URLFeatureExtractor:
    """
    Extract 40+ features from URLs for ML model prediction

    This class must be imported BEFORE loading the pickle file!
    """

    def __init__(self):
        self.suspicious_keywords = [
            'login', 'verify', 'account', 'confirm', 'update', 'secure',
            'banking', 'paypal', 'amazon', 'apple', 'microsoft', 'google',
            'password', 'signin', 'authenticate', 'authorize', 'validate',
            'credit', 'debit', 'card', 'bank', 'payment', 'transaction',
            'customer', 'support', 'urgent', 'suspended', 'limited', 'action'
        ]
        self.brand_names = [
            'amazon', 'paypal', 'apple', 'microsoft', 'google', 'facebook',
            'twitter', 'instagram', 'netflix', 'ebay', 'walmart', 'bank',
            'irs', 'ups', 'fedex', 'dhl', 'dropbox', 'icloud', 'linkedin'
        ]

        self.suspicious_tlds = ['tk', 'ml',
                                'ga', 'cf', 'ru', 'su', 'top', 'xyz']
        self.legitimate_tlds = ['com', 'org', 'net', 'edu', 'gov', 'co', 'uk']

    def extract_features(self, url):
        """Extract 40+ features from URL"""
        features = {}

        try:
            url = str(url).strip()
            if not url or url == 'nan' or len(url) < 3:
                return self._get_empty_features()
            # Add protocol if missing
            if not url.startswith('http'):
                url = 'http://' + url
            # === BASIC URL PROPERTIES ===
            features['url_length'] = len(url)
            features['has_https'] = 1 if url.startswith('https') else 0
            features['has_http'] = 1 if url.startswith('http') else 0
            # Parse URL
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path
            query = parsed.query

            # === DOMAIN ANALYSIS ===
            features['domain_length'] = len(domain)
            features['domain_entropy'] = self._calculate_entropy(domain)
            features['domain_has_numbers'] = 1 if any(
                c.isdigit() for c in domain) else 0
            # === SUBDOMAIN ANALYSIS ===
            subdomains = domain.split('.')
            features['subdomain_count'] = len(subdomains) - 1
            features['excessive_subdomains'] = 1 if len(subdomains) > 4 else 0

            if len(subdomains) > 2:
                subdomain_lengths = [len(s) for s in subdomains[:-1]]
                features['avg_subdomain_length'] = np.mean(subdomain_lengths)
                features['subdomain_length_variance'] = np.var(
                    subdomain_lengths)
            else:
                features['avg_subdomain_length'] = 0
                features['subdomain_length_variance'] = 0
            # === TLD ANALYSIS ===
            tld = subdomains[-1] if subdomains else ''
            features['tld_length'] = len(tld)
            features['suspicious_tld'] = 1 if tld in self.suspicious_tlds else 0
            features['legitimate_tld'] = 1 if tld in self.legitimate_tlds else 0
            features['country_tld'] = 1 if len(tld) == 2 else 0

            # === BRAND NAME SPOOFING ===
            domain_lower = domain.lower()
            brand_matches = [
                brand for brand in self.brand_names if brand in domain_lower]
            features['contains_brand_name'] = 1 if brand_matches else 0
            features['brand_name_count'] = len(brand_matches)
            max_similarity = 0
            for brand in self.brand_names:
                similarity = self._string_similarity(domain_lower, brand)
                max_similarity = max(max_similarity, similarity)
            features['max_brand_similarity'] = max_similarity

            # === PATH AND QUERY ===
            features['path_length'] = len(path)
            features['path_has_numbers'] = 1 if any(
                c.isdigit() for c in path) else 0
            features['query_length'] = len(query)
            features['query_param_count'] = len(
                parse_qs(query)) if query else 0
            features['has_suspicious_query'] = self._check_suspicious_query(
                query)
            # === SPECIAL CHARACTERS ===
            features['hyphen_count'] = url.count('-')
            features['underscore_count'] = url.count('_')
            features['dot_count'] = url.count('.')
            features['at_sign_count'] = url.count('@')
            features['percent_count'] = url.count('%')
            features['double_slash_count'] = url.count('//')

            # === CHARACTER DISTRIBUTION ===
            total_chars = len(domain)
            if total_chars > 0:
                features['digits_ratio'] = sum(
                    1 for c in domain if c.isdigit()) / total_chars
                features['uppercase_ratio'] = sum(
                    1 for c in domain if c.isupper()) / total_chars
                features['lowercase_ratio'] = sum(
                    1 for c in domain if c.islower()) / total_chars
                features['special_chars_ratio'] = sum(
                    1 for c in domain if c in '-._~') / total_chars
            else:
                features['digits_ratio'] = 0
                features['uppercase_ratio'] = 0
                features['lowercase_ratio'] = 0
                features['special_chars_ratio'] = 0

            # === SUSPICIOUS KEYWORDS ===
            url_lower = url.lower()
            keyword_matches = [
                kw for kw in self.suspicious_keywords if kw in url_lower]
            features['suspicious_keyword_count'] = len(keyword_matches)
            features['has_login'] = 1 if 'login' in url_lower else 0
            features['has_verify'] = 1 if 'verify' in url_lower else 0
            features['has_update'] = 1 if 'update' in url_lower else 0
            features['has_confirm'] = 1 if 'confirm' in url_lower else 0
            features['has_account'] = 1 if 'account' in url_lower else 0
            features['has_urgent'] = 1 if 'urgent' in url_lower else 0

            # === IP ADDRESS DETECTION ===
            features['has_ip_address'] = 1 if self._is_ip_address(
                domain) else 0
            features['is_invalid_ip'] = 1 if self._is_invalid_ip(domain) else 0

            # === URL ANOMALIES ===
            features['multiple_at_signs'] = 1 if url.count('@') > 1 else 0
            features['has_url_in_path'] = 1 if self._has_url_in_path(
                path) else 0
            features['has_port'] = 1 if ':' in domain else 0

            # === CHARACTER REPETITION ===
            features['max_char_repetition'] = self._max_char_repetition(domain)
            features['has_hyphen_in_domain'] = 1 if '-' in domain else 0

            # === URL ENCODING ===
            features['has_percent_encoding'] = 1 if '%' in url else 0
            features['percent_encoding_ratio'] = url.count(
                '%') / len(url) if len(url) > 0 else 0

        except Exception as e:
            return self._get_empty_features()

        return features

    def _get_empty_features(self):
        """Return feature dict with all zeros"""
        return {
            'url_length': 0, 'has_https': 0, 'has_http': 0,
            'domain_length': 0, 'domain_entropy': 0, 'domain_has_numbers': 0,
            'subdomain_count': 0, 'excessive_subdomains': 0,
            'avg_subdomain_length': 0, 'subdomain_length_variance': 0,
            'tld_length': 0, 'suspicious_tld': 0, 'legitimate_tld': 0, 'country_tld': 0,
            'contains_brand_name': 0, 'brand_name_count': 0, 'max_brand_similarity': 0,
            'path_length': 0, 'path_has_numbers': 0, 'query_length': 0,
            'query_param_count': 0, 'has_suspicious_query': 0,
            'hyphen_count': 0, 'underscore_count': 0, 'dot_count': 0,
            'at_sign_count': 0, 'percent_count': 0, 'double_slash_count': 0,
            'digits_ratio': 0, 'uppercase_ratio': 0, 'lowercase_ratio': 0,
            'special_chars_ratio': 0, 'suspicious_keyword_count': 0,
            'has_login': 0, 'has_verify': 0, 'has_update': 0, 'has_confirm': 0,
            'has_account': 0, 'has_urgent': 0, 'has_ip_address': 0, 'is_invalid_ip': 0,
            'multiple_at_signs': 0, 'has_url_in_path': 0, 'has_port': 0,
            'max_char_repetition': 0, 'has_hyphen_in_domain': 0,
            'has_percent_encoding': 0, 'percent_encoding_ratio': 0
        }

    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of text"""
        if not text or len(text) == 0:
            return 0
        entropy = 0
        text_len = len(text)
        for char in set(text):
            frequency = text.count(char) / text_len
            entropy -= frequency * np.log2(frequency)
        return entropy

    def _string_similarity(self, s1, s2):
        """Calculate string similarity (0-1)"""
        longer = s1 if len(s1) >= len(s2) else s2
        shorter = s2 if len(s1) >= len(s2) else s1
        if len(longer) == 0:
            return 1.0
        edit_distance = self._levenshtein_distance(longer, shorter)
        return (len(longer) - edit_distance) / float(len(longer))

    def _levenshtein_distance(self, s1, s2):
        """Calculate Levenshtein distance"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    def _is_ip_address(self, domain):
        """Check if domain is IP address"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, domain):
            return False
        parts = domain.split('.')
        for part in parts:
            try:
                num = int(part)
                if num > 255:
                    return False
            except:
                return False
        return True

    def _is_invalid_ip(self, domain):
        """Check if domain looks like invalid IP"""
        parts = domain.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit():
                return False
            try:
                num = int(part)
                if num > 255:
                    return True
            except:
                return False
        return False

    def _has_url_in_path(self, path):
        """Check if URL embedded in path"""
        return bool(re.search(r'https?://', path))

    def _max_char_repetition(self, text):
        """Find max consecutive character repetition"""
        if not text or len(text) == 0:
            return 0
        max_rep = 1
        current_rep = 1
        for i in range(1, len(text)):
            if text[i] == text[i-1]:
                current_rep += 1
                max_rep = max(max_rep, current_rep)
            else:
                current_rep = 1
        return max_rep

    def _check_suspicious_query(self, query):
        """Check for suspicious query parameters"""
        if not query:
            return 0

        suspicious_params = ['redirect', 'url',
                             'http', 'login', 'email', 'password']

        query_lower = query.lower()
        return 1 if any(param in query_lower for param in suspicious_params) else 0
