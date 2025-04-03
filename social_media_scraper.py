import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException, WebDriverException, NoSuchElementException

# Social media profile URLs
SOCIAL_MEDIA_URLS = {
    "Facebook": "https://www.facebook.com/{}",
    "Instagram": "https://www.instagram.com/{}/",
    "Twitter": "https://twitter.com/{}",
    "LinkedIn": "https://www.linkedin.com/in/{}",
    "GitHub": "https://github.com/{}",
    "TikTok": "https://www.tiktok.com/@{}"
}

def setup_driver():
    """Set up the Selenium WebDriver in headless mode with proper settings."""
    options = Options()
    options.add_argument("--headless")  # Run in headless mode (no GUI)
    options.add_argument("--disable-gpu")  # Fix WebGL errors
    options.add_argument("--disable-software-rasterizer")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--ignore-certificate-errors")  # Fix SSL handshake failures
    options.add_argument("--disable-features=SSLKeyLogging")
    options.add_argument("--enable-features=NetworkService,NetworkServiceInProcess")
    options.add_argument("start-maximized")
    options.add_argument("--disable-blink-features=AutomationControlled")  # Bypass bot detection

    # Set a User-Agent to avoid detection as a bot
    options.add_argument(
        "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.177 Safari/537.36"
    )

    # Use WebDriver Manager to get the latest ChromeDriver
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=options)
    driver.set_page_load_timeout(15)  # Max 15 seconds per site
    return driver

def check_username(username):
    """Check if a username exists on different social media platforms."""
    driver = setup_driver()
    results = {}

    for platform, url in SOCIAL_MEDIA_URLS.items():
        profile_url = url.format(username)
        print(f"🔹 Checking {platform}...")

        try:
            driver.get(profile_url)
            time.sleep(2)  # Allow page to load
            
            # Check for error messages indicating a non-existent profile
            if "Page Not Found" in driver.title or "Sorry, this page isn't available" in driver.page_source:
                results[platform] = {"exists": False}
            else:
                results[platform] = {"exists": True, "profile_url": profile_url}

        except TimeoutException:
            print(f"⚠️ Timeout while loading {platform}")
            results[platform] = {"error": "Timeout"}
        except WebDriverException as e:
            print(f"⚠️ WebDriver Error for {platform}: {e}")
            results[platform] = {"error": str(e)}

    driver.quit()
    return results

if __name__ == "__main__":
    username = input("🔹 Enter the username to check: ")
    results = check_username(username)

    print("\n🔹 Results:")
    for platform, data in results.items():
        if data.get("exists"):
            print(f"✅ {platform}: Found at {data['profile_url']}")
        elif data.get("error"):
            print(f"⚠️ {platform}: {data['error']}")
        else:
            print(f"❌ {platform}: Not found")
