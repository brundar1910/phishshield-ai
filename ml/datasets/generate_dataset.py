"""
Dataset Generator for Phishing Detection.
Generates a representative, clean, balanced dataset of benign and phishing URLs
grounded in real-world threat intelligence attack vectors and trusted web domains.
"""

import csv
import os
from typing import List, Tuple

# Sample representative domains and patterns for Benign URLs (Label: 0)
BENIGN_TEMPLATES = [
    # Search & Portals
    "https://www.google.com/search?q={term}",
    "https://www.bing.com/search?q={term}&form=QBLH",
    "https://duckduckgo.com/?q={term}&t=h_&ia=web",
    "https://search.yahoo.com/search?p={term}",
    # E-Commerce & Retail
    "https://www.amazon.com/dp/{token}?ref=nb_sb_noss",
    "https://www.ebay.com/itm/{num}",
    "https://www.walmart.com/ip/{term}/{num}",
    "https://www.target.com/p/{term}/-/A-{num}",
    "https://www.bestbuy.com/site/{term}/{num}.p",
    "https://store.steampowered.com/app/{num}/{term}",
    # Tech & Developer Platforms
    "https://github.com/{user}/{repo}",
    "https://gitlab.com/{user}/{repo}/-/tree/main",
    "https://stackoverflow.com/questions/{num}/{term}",
    "https://pypi.org/project/{term}/",
    "https://developer.mozilla.org/en-US/docs/Web/{term}",
    "https://aws.amazon.com/blogs/aws/{term}-{num}/",
    "https://cloud.google.com/docs/{term}/overview",
    "https://learn.microsoft.com/en-us/azure/{term}/quickstart",
    "https://hub.docker.com/r/{user}/{repo}",
    "https://hub.docker.com/_/{term}",
    "https://crates.io/crates/{term}",
    "https://www.npmjs.com/package/{term}",
    # Academic & Government
    "https://www.mit.edu/research/{term}",
    "https://stanford.edu/dept/{term}/courses",
    "https://harvard.edu/programs/{term}",
    "https://berkeley.edu/academics/{term}",
    "https://ox.ac.uk/admissions/{term}",
    "https://cam.ac.uk/research/{term}",
    "https://www.nasa.gov/mission_pages/{term}/main/index.html",
    "https://www.cdc.gov/{term}/index.html",
    "https://www.nih.gov/health-information/{term}",
    "https://www.irs.gov/forms-pubs/{term}",
    "https://www.usa.gov/{term}",
    "https://europa.eu/european-union/about-eu/{term}_en",
    # Media, Knowledge & Community
    "https://en.wikipedia.org/wiki/{term}",
    "https://www.nytimes.com/section/{term}",
    "https://www.bbc.com/news/{term}-{num}",
    "https://www.theguardian.com/{term}/article/{num}",
    "https://medium.com/@{user}/{term}-{num}",
    "https://reddit.com/r/{term}/comments/{token}",
    "https://news.ycombinator.com/item?id={num}",
    "https://arxiv.org/abs/{num}.{num2}",
    "https://ted.com/talks/{user}_{term}",
    "https://nationalgeographic.com/environment/article/{term}",
    # Social & Professional
    "https://www.linkedin.com/in/{user}-{token}",
    "https://twitter.com/{user}/status/{num}",
    "https://instagram.com/{user}",
    "https://facebook.com/groups/{num}",
    # Corporate & Services
    "https://www.netflix.com/title/{num}",
    "https://spotify.com/playlist/{token}",
    "https://dropbox.com/s/{token}/{term}.pdf?dl=0",
    "https://slack.com/apps/{token}-{term}",
    "https://zoom.us/j/{num}?pwd={token}",
    "https://atlassian.com/software/jira/{term}"
]

# Sample representative patterns for Phishing URLs (Label: 1)
PHISHING_PATTERNS = [
    # IP Address Based Attacks
    "http://192.168.1.{num}/{brand}/login.php",
    "http://10.0.0.{num}/{brand}-secure/verification.html",
    "http://172.16.254.{num}/webscr?cmd=_login-run&dispatch={token}",
    "http://45.33.32.{num}/online-banking/{brand}/sign-in",
    "http://185.190.140.{num}/service/account-update.php",
    "http://103.224.182.{num}/auth/identity/confirm",
    # Domain Impersonation & Typosquatting
    "http://www.{brand}-security-update.com/login",
    "http://www.{brand}-verification-center.net/account",
    "http://{brand}.com-account-recovery.xyz/auth",
    "http://{brand}-customer-service-alert.top/verify",
    "http://secure-{brand}-login-portal.work/sign-in",
    "http://update-{brand}-billing-details.click/confirm",
    "http://{brand}verify-billing-info.buzz/identity",
    "http://account-{brand}-security-notification.fit/auth",
    "http://my-{brand}-portal-login.gq/session",
    "http://{brand}-support-desk-help.ml/login.asp",
    # Subdomain Abuse / Embedded Brand Tricks
    "http://{brand}.com.account-update.xyz/login.php?ref={token}",
    "http://{brand}.com.verify-billing-card.top/auth/session={token}",
    "http://signin.{brand}.com.security-protection.club/index.html",
    "http://help.{brand}.com.support-desk-ticket.monster/auth",
    "http://online.{brand}.com.ebanking-access.cam/login",
    "http://verify.{brand}.com.banking-service.icu/security",
    # Credential Obfuscation with @ Symbol
    "http://{brand}.com:security-login@{phish_domain}/verify.php",
    "http://www.{brand}.com@login-{phish_domain}/account-access",
    "http://support.{brand}.com@{phish_domain}/update-credentials",
    # URL Shorteners with deceptive landing hints
    "https://bit.ly/{token}?{brand}_secure_login",
    "https://tinyurl.com/{token}?redirect={brand}_verify",
    "https://is.gd/{token}#{brand}_account_update",
    "https://cutt.ly/{token}?login_session={brand}",
    "https://t.co/{token}?{brand}_security_notice",
    # Multi-subdomain deep hierarchy deceptive paths
    "http://ssl.{brand}.secure.login.client.security-update.xyz/auth/{token}",
    "http://online.banking.account.verification.{brand}.protection.top/signin",
    "http://secure.account.update.service.portal.{phish_domain}/confirm.aspx",
    # Double slash in path redirects
    "http://{phish_domain}/redirect//https://{brand}.com/login",
    "http://{brand}-verify.com/login.php//secure//auth?session={token}",
    # Suspicious Port + Hex/Octal IP
    "http://192.168.1.{num}:8080/{brand}/account-locked.html",
    "http://45.12.32.{num}:8443/secure/{brand}/login",
    "http://0x5b.0x2f.0xa1.0x12/{brand}/verify"
]

BRANDS = [
    "paypal", "netflix", "apple", "microsoft", "amazon", "chase",
    "wellsfargo", "bankofamerica", "citi", "google", "facebook",
    "instagram", "dhl", "fedex", "usps", "binance", "coinbase",
    "metamask", "dropbox", "docuplay", "adobe", "outlook", "yahoo"
]

PHISH_DOMAINS = [
    "secureserver-alert.com", "billing-update-center.org",
    "account-verification-support.net", "identity-confirm-portal.info",
    "safety-check-system.xyz", "customer-service-helpdesk.top",
    "cloud-protection-auth.club", "online-token-validator.live",
    "session-security-renew.click", "protection-gateway-login.buzz"
]

TERMS = [
    "python", "machine-learning", "cybersecurity", "neural-network", "docker",
    "kubernetes", "database", "encryption", "algorithms", "software-design",
    "cloud-computing", "linux-kernel", "networking", "data-structures",
    "distributed-systems", "compiler", "operating-systems", "web-assembly",
    "quantum-computing", "robotics", "computer-vision", "signal-processing"
]

USERS = [
    "torvalds", "octocat", "google", "microsoft", "apache", "mozilla",
    "facebook", "aws", "openai", "tensorflow", "pytorch", "elastic",
    "angular", "vuejs", "docker", "ansible", "django", "pallets"
]

REPOS = [
    "linux", "core-api", "transformers", "scikit-learn", "react", "vscode",
    "kubernetes", "cpython", "pandas", "numpy", "flask", "fastapi",
    "tensorflow", "keras", "redis", "nginx", "postgres", "node"
]


def generate_dataset(target_path: str, count_per_class: int = 750) -> Tuple[int, int]:
    """Generates balanced dataset and saves to CSV."""
    urls = []
    seen = set()

    # 1. Generate Benign URLs
    benign_count = 0
    t_idx = 0
    while benign_count < count_per_class:
        template = BENIGN_TEMPLATES[t_idx % len(BENIGN_TEMPLATES)]
        term = TERMS[(benign_count * 3) % len(TERMS)]
        user = USERS[(benign_count * 2) % len(USERS)]
        repo = REPOS[(benign_count * 5) % len(REPOS)]
        num = 100000 + (benign_count * 79)
        num2 = 1000 + (benign_count * 13)
        token = f"x7f{benign_count}b9a"

        url = template.format(term=term, user=user, repo=repo, num=num, num2=num2, token=token)
        if url not in seen:
            seen.add(url)
            urls.append((url, 0))
            benign_count += 1
        t_idx += 1

    # 2. Generate Phishing URLs
    phish_count = 0
    p_idx = 0
    while phish_count < count_per_class:
        pattern = PHISHING_PATTERNS[p_idx % len(PHISHING_PATTERNS)]
        brand = BRANDS[(phish_count * 2) % len(BRANDS)]
        phish_domain = PHISH_DOMAINS[(phish_count * 3) % len(PHISH_DOMAINS)]
        num = (phish_count % 250) + 1
        token = f"auth_token_{phish_count:04d}_sess"

        url = pattern.format(brand=brand, phish_domain=phish_domain, num=num, token=token)
        if url not in seen:
            seen.add(url)
            urls.append((url, 1))
            phish_count += 1
        p_idx += 1

    # Ensure parent directory exists
    os.makedirs(os.path.dirname(target_path), exist_ok=True)

    # Write to CSV
    with open(target_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        for url, label in urls:
            writer.writerow([url, label])

    return benign_count, phish_count


if __name__ == "__main__":
    dataset_file = os.path.join(os.path.dirname(__file__), "urls_dataset.csv")
    b, p = generate_dataset(dataset_file, count_per_class=750)
    print(f"Dataset generated successfully at {dataset_file} with {b} benign and {p} phishing URLs (Total: {b+p}).")
