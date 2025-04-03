import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from selenium.common.exceptions import WebDriverException, TimeoutException, NoSuchElementException

# Social media platforms and their profile URL patterns
SOCIAL_MEDIA_URLS = {
    "Facebook": "https://www.facebook.com/{}",
    "Instagram": "https://www.instagram.com/{}/",
    "Twitter": "https://twitter.com/{}",
    "LinkedIn": "https://www.linkedin.com/in/{}",
    "GitHub": "https://github.com/{}",
    "TikTok": "https://www.tiktok.com/@{}"
}

def setup_driver():
    """Set up the headless Selenium WebDriver."""
    options = Options()
    options.add_argument("--headless")  # Run in headless mode (no GUI)
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("start-maximized")
    options.add_argument("disable-infobars")
    options.add_argument("--disable-blink-features=AutomationControlled")  # Avoid bot detection

    # Use WebDriver Manager to get the latest ChromeDriver
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=options)
    return driver

def check_username(username):
    """Check if a username exists on different social media platforms."""
    driver = setup_driver()
    results = {}

    for platform, url in SOCIAL_MEDIA_URLS.items():
        profile_url = url.format(username)
        print(f"Checking {platform}...")

        try:
            driver.get(profile_url)
            time.sleep(3)  # Wait for page to load
            
            # Check for 404 or non-existing profile elements
            if "Page Not Found" in driver.title or "Sorry, this page isn't available" in driver.page_source:
                results[platform] = {"exists": False}
            else:
                results[platform] = {"exists": True, "profile_url": profile_url}

        except (TimeoutException, WebDriverException, NoSuchElementException) as e:
            results[platform] = {"error": f"Error checking {platform}: {e}"}

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
