from bs4 import BeautifulSoup
import re
import os
import base64

# Suspicious patterns for detecting malicious content
SUSPICIOUS_KEYWORDS = ["free", "login", "verify", "update", "account", "secure", "click", "instant", "password", "confidential", "urgent"]
SUSPICIOUS_SCRIPTS = ["eval", "document.cookie", "window.location", "location.href", "setTimeout", "setInterval"]
SUSPICIOUS_IFRAMES = ["srcdoc", "sandbox", "javascript:", "data:text/html"]
SUSPICIOUS_META_TAGS = ["refresh", "robots"]
SUSPICIOUS_LINK_PATTERNS = [r"javascript:", r"data:text/html", r"file://", r"about:", r"eval"]
SUSPICIOUS_EXTERNAL_DOMAINS = ["malicious.com", "example.com"]

def check_suspicious_keywords(content):
    """Check if any suspicious keywords are found in the page content."""
    return any(keyword in content.lower() for keyword in SUSPICIOUS_KEYWORDS)

def check_suspicious_scripts(scripts):
    """Check if any suspicious script patterns are found."""
    for script in scripts:
        if any(pattern in script for pattern in SUSPICIOUS_SCRIPTS):
            return True
    return False

def check_suspicious_iframes(iframes):
    """Check if any suspicious iframe patterns are found."""
    for iframe in iframes:
        if any(pattern in iframe.get('src', '') for pattern in SUSPICIOUS_IFRAMES):
            return True
    return False

def check_suspicious_meta_tags(meta_tags):
    """Check for suspicious meta tags."""
    for meta in meta_tags:
        if any(tag in meta.attrs.get('name', '').lower() or meta.attrs.get('http-equiv', '').lower() for tag in SUSPICIOUS_META_TAGS):
            return True
    return False

def check_hidden_elements(elements):
    """Check for hidden elements that could be used for malicious purposes."""
    for element in elements:
        if 'style' in element.attrs:
            style = element.attrs['style'].lower()
            if 'display:none' in style or 'visibility:hidden' in style:
                return True
    return False

def check_base64_payload(content):
    """Check if there's any base64-encoded data, which could indicate obfuscated malicious content."""
    base64_patterns = re.compile(r'(data:image|data:audio|data:text|data:video)[^"]*base64,')
    return bool(base64_patterns.search(content))

def check_suspicious_links(links):
    """Check for suspicious links."""
    for link in links:
        href = link.get('href', '')
        if any(re.search(pattern, href) for pattern in SUSPICIOUS_LINK_PATTERNS):
            return True
        if any(domain in href for domain in SUSPICIOUS_EXTERNAL_DOMAINS):
            return True
    return False

def analyze_html(html_path):
    """Analyze the saved HTML content to detect malicious content."""
    if not os.path.exists(html_path):
        print(f"❌ The file {html_path} does not exist.")
        return

    with open(html_path, 'r', encoding='utf-8') as file:
        content = file.read()

    soup = BeautifulSoup(content, 'html.parser')

    # Check for suspicious keywords in the body text
    print("Checking for suspicious keywords...")
    body_content = soup.get_text()
    if check_suspicious_keywords(body_content):
        print("⚠️ Suspicious keywords detected in page content.")
    else:
        print("✅ No suspicious keywords found in page content.")

    # Check for suspicious scripts
    print("Checking for suspicious scripts...")
    scripts = soup.find_all('script')
    script_contents = [script.string for script in scripts if script.string]
    if check_suspicious_scripts(script_contents):
        print("⚠️ Suspicious script patterns detected.")
    else:
        print("✅ No suspicious scripts found.")

    # Check for suspicious iframes
    print("Checking for suspicious iframes...")
    iframes = soup.find_all('iframe')
    if check_suspicious_iframes(iframes):
        print("⚠️ Suspicious iframe sources detected.")
    else:
        print("✅ No suspicious iframes found.")

    # Check for suspicious meta tags
    print("Checking for suspicious meta tags...")
    meta_tags = soup.find_all('meta')
    if check_suspicious_meta_tags(meta_tags):
        print("⚠️ Suspicious meta tags detected.")
    else:
        print("✅ No suspicious meta tags found.")

    # Check for hidden elements
    print("Checking for hidden elements...")
    hidden_elements = soup.find_all(True, {'style': True})
    if check_hidden_elements(hidden_elements):
        print("⚠️ Hidden elements detected.")
    else:
        print("✅ No hidden elements found.")

    # Check for base64 payloads
    print("Checking for base64-encoded payloads...")
    if check_base64_payload(content):
        print("⚠️ Base64-encoded payload detected.")
    else:
        print("✅ No base64-encoded payloads found.")

    # Check for suspicious links
    print("Checking for suspicious links...")
    links = soup.find_all('a')
    if check_suspicious_links(links):
        print("⚠️ Suspicious links detected.")
    else:
        print("✅ No suspicious links found.")

    # Final result
    print("\n🔍 HTML Analysis Completed:")
    print(f"   Keywords: {'Suspicious' if check_suspicious_keywords(body_content) else 'Safe'}")
    print(f"   Scripts: {'Suspicious' if check_suspicious_scripts(script_contents) else 'Safe'}")
    print(f"   Iframes: {'Suspicious' if check_suspicious_iframes(iframes) else 'Safe'}")
    print(f"   Meta Tags: {'Suspicious' if check_suspicious_meta_tags(meta_tags) else 'Safe'}")
    print(f"   Hidden Elements: {'Suspicious' if check_hidden_elements(hidden_elements) else 'Safe'}")
    print(f"   Base64 Payloads: {'Suspicious' if check_base64_payload(content) else 'Safe'}")
    print(f"   Links: {'Suspicious' if check_suspicious_links(links) else 'Safe'}")

if __name__ == "__main__":
    html_file_path = input("Enter the path to the saved HTML file: ").strip()
    analyze_html(html_file_path)
