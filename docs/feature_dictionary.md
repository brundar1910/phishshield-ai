# Feature Dictionary: URL Phishing Detection

The feature extraction engine (`backend/feature_extraction/url_features.py`) calculates 29 numerical and boolean signals for every analyzed URL.

| # | Feature Name | Type | Description |
|---|--------------|------|-------------|
| 1 | `url_length` | Integer | Total character length of full URL. Phishing URLs often use lengthy paths to hide target payloads. |
| 2 | `hostname_length` | Integer | Length of the domain name / hostname. |
| 3 | `path_length` | Integer | Length of the URL path component. |
| 4 | `query_length` | Integer | Length of query string parameters. |
| 5 | `count_dots` | Integer | Number of dots (`.`) in full URL. |
| 6 | `count_dots_hostname` | Integer | Number of dots in hostname (indicator of deep subdomains). |
| 7 | `count_hyphens` | Integer | Total hyphens in URL. |
| 8 | `count_hyphens_hostname`| Integer | Hyphens in domain name (common in typosquatting and brand spoofing). |
| 9 | `count_underscores` | Integer | Underscores in URL. |
| 10 | `count_slashes` | Integer | Slashes (`/`) in URL path. |
| 11 | `count_question_marks` | Integer | Question marks in URL. |
| 12 | `count_equals` | Integer | Equals signs (`=`) indicating parameter assignments. |
| 13 | `count_at` | Integer | Presence of `@` symbol (often used to obscure preceding credentials). |
| 14 | `count_exclamation` | Integer | Exclamation points (`!`). |
| 15 | `count_percent` | Integer | Percent signs (`%`) used in URL hex encoding / obfuscation. |
| 16 | `count_ampersand` | Integer | Ampersands (`&`) connecting query parameters. |
| 17 | `count_subdomains` | Integer | Total subdomain depth (e.g. `sub2.sub1.domain.com` has 2 subdomains). |
| 18 | `has_ip` | Boolean | 1 if hostname is an IPv4 or hex/octal IP address, 0 otherwise. |
| 19 | `is_https` | Boolean | 1 if protocol is HTTPS, 0 if plain HTTP. |
| 20 | `is_shortened` | Boolean | 1 if domain matches a known URL shortening provider (bit.ly, tinyurl, etc.). |
| 21 | `suspicious_keyword_count` | Integer | Count of credential-harvesting keywords (login, verify, banking, token, etc.). |
| 22 | `shannon_entropy` | Float | Shannon entropy of the domain name (flags algorithmically generated domains / DGA). |
| 23 | `digit_count_hostname` | Integer | Number of numeric digits in hostname. |
| 24 | `digit_ratio_hostname` | Float | Ratio of digits to total characters in domain name. |
| 25 | `suspicious_tld` | Boolean | 1 if TLD belongs to high-abuse TLDs (.xyz, .top, .buzz, .click, etc.). |
| 26 | `hyphen_in_domain` | Boolean | 1 if domain name contains hyphen. |
| 27 | `double_slash_redirect`| Boolean | 1 if path contains `//` redirect evasion pattern. |
| 28 | `has_port` | Boolean | 1 if a non-standard port (other than 80 or 443) is explicitly declared. |
| 29 | `tld_in_subdomain` | Boolean | 1 if subdomains contain deceptive TLD strings (e.g. `paypal.com.attacker.com`). |
