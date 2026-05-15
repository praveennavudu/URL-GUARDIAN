from urllib.parse import urlparse

TRUSTED_DOMAINS = [
    "google.com",
    "facebook.com",
    "youtube.com",
    "amazon.com",
    "wikipedia.org",
    "twitter.com",
    "instagram.com",
    "linkedin.com",
    "github.com",
    "microsoft.com",
    "apple.com"
]


def extract_domain(url):
    if not url.startswith("http"):
        url = "http://" + url

    parsed = urlparse(url)
    return parsed.netloc.lower()


def is_trusted_domain(url):
    domain = extract_domain(url)

    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith("." + trusted):
            return True
    return False