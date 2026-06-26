import os
import time
import winreg
import undetected_chromedriver as uc

def get_chrome_version() -> int:
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Google\Chrome\BLBeacon")
        val, _ = winreg.QueryValueEx(key, "version")
        return int(val.split(".")[0])
    except Exception:
        return 149

def main():
    profile_dir = r"F:\projects\Auto_Payment_checker_iran\automation_profile_selenium"
    print(f"[*] Launching Chrome with profile: {profile_dir}")

    # Clean Chrome lock files
    files_to_delete = ["SingletonLock", "SingletonSocket", "SingletonCookie", "LOCK", "DevToolsActivePort"]
    for root, dirs, files in os.walk(profile_dir):
        for f in files:
            if any(x in f for x in files_to_delete):
                try:
                    os.remove(os.path.join(root, f))
                except:
                    pass
        break

    options = uc.ChromeOptions()
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--headless")

    chrome_version = get_chrome_version()
    driver = uc.Chrome(
        user_data_dir=profile_dir,
        options=options,
        version_main=chrome_version
    )

    try:
        driver.get("https://yeswehack.com/programs")
        time.sleep(5)
        print(f"[+] Current URL: {driver.current_url}")
        
        # Check localStorage
        token = driver.execute_script("return window.localStorage.getItem('token') || window.localStorage.getItem('jwt') || window.localStorage.getItem('auth') || window.localStorage.getItem('ngStorage-token');")
        print(f"[+] LocalStorage Token: {token}")
        
        # Print all localStorage keys
        keys = driver.execute_script("return Object.keys(window.localStorage);")
        print(f"[+] LocalStorage Keys: {keys}")
        
        # Print cookies
        cookies = driver.get_cookies()
        print(f"[+] Found {len(cookies)} cookies.")
        for c in cookies:
            print(f"  Cookie: {c['name']} = {c['value'][:40]}...")
            
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        driver.quit()

if __name__ == "__main__":
    main()
