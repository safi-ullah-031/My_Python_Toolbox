import requests
import json
import pandas as pd
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options

# List of platforms to check username availability
SOCIAL_MEDIA_URLS = {
    "Twitter": "https://twitter.com/{}",
    "Instagram": "https://www.instagram.com/{}",
    "Facebook": "https://www.facebook.com/{}",
    "GitHub": "https://github.com/{}",
    "TikTok": "https://www.tiktok.com/@{}"
}

# Function to check username availability
def check_username(username):
    results = {}
    for platform, url in SOCIAL_MEDIA_URLS.items():
        profile_url = url.format(username)
        response = requests.get(profile_url)

        if response.status_code == 200:
            results[platform] = {"exists": True, "profile_url": profile_url}
        else:
            results[platform] = {"exists": False}

    return results

# Function to scrape Twitter bio using BeautifulSoup
def scrape_twitter_profile(username):
    url = f"https://twitter.com/{username}"
    response = requests.get(url)

    if response.status_code != 200:
        return {"error": "Profile not found"}

    soup = BeautifulSoup(response.text, "html.parser")
    profile_info = {
        "name": soup.find("title").text,
        "bio": soup.find("meta", {"name": "description"})["content"]
    }

    return profile_info

# Function to scrape Instagram bio using Selenium
def scrape_instagram(username):
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Runs in background
    driver = webdriver.Chrome(service=Service("chromedriver.exe"), options=chrome_options)

    url = f"https://www.instagram.com/{username}/"
    driver.get(url)

    profile_info = {"username": username}

    try:
        profile_info["bio"] = driver.find_element(By.XPATH, "//meta[@name='description']").get_attribute("content")
    except:
        profile_info["error"] = "Profile not found or blocked"

    driver.quit()
    return profile_info

# Function to save data to CSV
def save_to_csv(data, filename="profiles.csv"):
    df = pd.DataFrame(data)
    df.to_csv(filename, index=False)
    print(f"✅ Data saved to {filename}")

# Function to save data to JSON
def save_to_json(data, filename="profiles.json"):
    with open(filename, "w") as file:
        json.dump(data, file, indent=4)
    print(f"✅ Data saved to {filename}")

# Main function to execute the tool
if __name__ == "__main__":
    username = input("🔹 Enter the username to check: ")
    
    # Step 1: Check Username Availability
    results = check_username(username)
    
    # Step 2: Scrape Profile Information
    twitter_data = scrape_twitter_profile(username)
    instagram_data = scrape_instagram(username)

    # Combine results
    final_data = {
        "username": username,
        "availability": results,
        "twitter_data": twitter_data,
        "instagram_data": instagram_data
    }

    # Step 3: Save Data
    save_to_csv([final_data])  # Save as CSV
    save_to_json(final_data)   # Save as JSON

    # Step 4: Display Results
    print(json.dumps(final_data, indent=4))
