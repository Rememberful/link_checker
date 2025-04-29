import asyncio
import aiohttp
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, quote
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

# Your VirusTotal API key
API_KEY = ""

# Suspicious keywords to flag
SUSPICIOUS_KEYWORDS = ["free", "login", "verify", "update", "account", "secure", "click"]

async def resolve_redirects(url):
    print(f"\n🔗 Checking URL: {url}")
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, allow_redirects=True) as response:
                history = [str(resp.url) for resp in response.history]
                final_url = str(response.url)
                print("➡️ Redirection Path: ")
                for i, step in enumerate(history + [final_url]):
                    print(f"   Step {i+1}: {step}")
                return final_url
        except Exception as e:
            print(f"❌ Failed to resolve redirects: {e}")
            return url

async def fetch_title(url):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                title = soup.title.string if soup.title else "No title found"
                print(f"📄 Page Title: {title}")
                return title
    except Exception as e:
        print(f"❌ Failed to fetch page title: {e}")
        return "No title found"

async def analyze_with_virustotal(url):
    url_id = quote(url, safe='')
    headers = {
        "x-apikey": API_KEY
    }
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    response = requests.get(vt_url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        print(f"🛡️ VirusTotal Detection:\n   ✅ Harmless: {stats['harmless']}\n   ⚠️ Suspicious: {stats['suspicious']}\n   ❌ Malicious: {stats['malicious']}")
    elif response.status_code == 404:
        print("❌ VirusTotal: URL not found in the database.")
        return False
    else:
        print(f"❌ Failed to retrieve analysis from VirusTotal: {response.text}")
        return False
    return True

def take_screenshot_and_html(url):
    print("📸 Opening page in headless browser...")
    options = webdriver.ChromeOptions()
    options.add_argument('--headless=new')  # for Chrome >= 109
    options.add_argument('--disable-gpu')
    options.add_argument('--no-sandbox')

    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    driver.set_window_size(1200, 800)
    driver.get(str(url))  # Ensure it's a string

    parsed = urlparse(url)
    domain = parsed.netloc.replace(".", "_")
    path = parsed.path.strip("/").replace("/", "_")
    base_name = f"{domain}_{path or 'home'}"

    # Save Screenshot
    screenshot_path = f"{base_name}.png"
    driver.save_screenshot(screenshot_path)
    print(f"✅ Screenshot saved as: {screenshot_path}")

    # Save HTML
    html_path = f"{base_name}.html"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(driver.page_source)
    print(f"✅ HTML content saved as: {html_path}")

    driver.quit()

async def check_link(input_url):
    final_url = await resolve_redirects(input_url)
    title = await fetch_title(final_url)

    if any(keyword in final_url.lower() or keyword in title.lower() for keyword in SUSPICIOUS_KEYWORDS):
        print("⚠️ Warning: This link contains suspicious keywords.")

    found = await analyze_with_virustotal(final_url)
    if not found:
        take_screenshot_and_html(final_url)

if __name__ == "__main__":
    user_url = input("Paste the URL to check: ").strip()
    asyncio.run(check_link(user_url))
