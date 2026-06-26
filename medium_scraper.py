import os
import sys
import time
import re
import datetime
import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys

# Overwrite default print to include local timestamps automatically
_original_print = print
def timestamped_print(*args, **kwargs):
    if not args:
        _original_print(**kwargs)
        return
    
    timestamp = datetime.datetime.now().strftime("[%H:%M:%S]")
    if kwargs.get("end") == "\r":
        _original_print(f"{timestamp} {args[0]}", **kwargs)
    else:
        if isinstance(args[0], str):
            _original_print(f"{timestamp} {args[0]}", *args[1:], **kwargs)
        else:
            _original_print(timestamp, *args, **kwargs)

print = timestamped_print

def get_chrome_version():
    """Detect local Google Chrome version on Windows."""
    chrome_version = None
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Google\Chrome\BLBeacon")
        val, _ = winreg.QueryValueEx(key, "version")
        chrome_version = int(val.split(".")[0])
    except Exception:
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome")
            val, _ = winreg.QueryValueEx(key, "DisplayVersion")
            chrome_version = int(val.split(".")[0])
        except Exception:
            pass
    if chrome_version:
        print(f"🔍 System Chrome version detected: {chrome_version}")
    else:
        print("⚠️ Chrome version could not be detected. Falling back to default: 120")
        chrome_version = 120
    return chrome_version

def clean_filename(title):
    """Sanitize the article title to create a safe filename."""
    title = re.sub(r'[^\w\s-]', '', title)
    title = re.sub(r'[\s_]+', '_', title).strip()
    return title[:60]

def convert_to_markdown_js():
    """JS script to run in the page context to convert the Medium article to Markdown format."""
    return """
    let article = document.querySelector('article');
    if (!article) {
        article = document.querySelector('main') || document.body;
    }
    if (!article) return null;

    let markdown = '';
    const titleEl = article.querySelector('h1');
    if (titleEl) {
        markdown += '# ' + titleEl.innerText.trim() + '\\n\\n';
    }

    // Capture article main metadata if available (author, date/read time)
    const authorEl = document.querySelector('[data-testid="authorName"]');
    const publishDateEl = document.querySelector('[data-testid="storyPublishDate"]');
    
    if (authorEl || publishDateEl) {
        markdown += '> **Author**: ' + (authorEl ? authorEl.innerText.trim() : 'Unknown') + '\\n';
        if (publishDateEl) {
            markdown += '> **Published**: ' + publishDateEl.innerText.trim() + '\\n';
        }
        markdown += '\\n---\\n\\n';
    }

    // Select all paragraphs, headings, lists, code blocks, images
    const elements = article.querySelectorAll('p, h2, h3, h4, pre, ul, ol, img');
    
    elements.forEach(el => {
        // Skip child elements of code blocks and list structures to avoid duplication
        if (el.closest('pre') && el.tagName.toLowerCase() !== 'pre') return;
        if (el.closest('ul') && el.tagName.toLowerCase() !== 'ul') return;
        if (el.closest('ol') && el.tagName.toLowerCase() !== 'ol') return;
        
        const tag = el.tagName.toLowerCase();
        const text = el.innerText ? el.innerText.trim() : '';
        
        if (tag === 'h2') {
            markdown += '## ' + text + '\\n\\n';
        } else if (tag === 'h3') {
            markdown += '### ' + text + '\\n\\n';
        } else if (tag === 'h4') {
            markdown += '#### ' + text + '\\n\\n';
        } else if (tag === 'p') {
            markdown += text + '\\n\\n';
        } else if (tag === 'pre') {
            markdown += '```\\n' + text + '\\n```\\n\\n';
        } else if (tag === 'ul' || tag === 'ol') {
            const items = el.querySelectorAll('li');
            items.forEach(li => {
                markdown += '- ' + li.innerText.trim() + '\\n';
            });
            markdown += '\\n';
        } else if (tag === 'img') {
            const src = el.getAttribute('src');
            const alt = el.getAttribute('alt') || 'image';
            // Filter out tiny avatars or icons
            if (src && !src.startsWith('data:') && !src.includes('/resize:fill:40:40/')) {
                markdown += '![' + alt + '](' + src + ')\\n\\n';
            }
        }
    });
    return markdown;
    """

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    automation_dir = os.path.join(script_dir, "medium_scraper_profile")
    output_dir = os.path.join(script_dir, "xss_writeups")
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"📁 Chrome Profile directory: {automation_dir}")
    print(f"📁 Output Markdown directory: {output_dir}")

    # Load progress tracking history
    scraped_history_file = os.path.join(script_dir, "scraped_urls.txt")
    scraped_urls = set()
    if os.path.exists(scraped_history_file):
        with open(scraped_history_file, "r", encoding="utf-8") as f:
            scraped_urls = {line.strip() for line in f if line.strip()}
    print(f"📖 Loaded {len(scraped_urls)} previously scraped URL(s) from history.")

    # Process cleanup
    try:
        import subprocess
        subprocess.run("taskkill /f /im chrome.exe", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run("taskkill /f /im chromedriver.exe", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as cleanup_err:
        pass

    # Ensure profile locks are cleaned
    if os.path.exists(automation_dir):
        files_to_delete = ["SingletonLock", "SingletonSocket", "SingletonCookie", "LOCK", "DevToolsActivePort"]
        for root, dirs, files in os.walk(automation_dir):
            for f in files:
                if any(x in f for x in files_to_delete):
                    try:
                        os.remove(os.path.join(root, f))
                    except:
                        pass
            break

    # Setup Undetected Options
    chrome_version = get_chrome_version()
    options = uc.ChromeOptions()
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--mute-audio")
    options.add_argument("--start-maximized")
    options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

    try:
        print("🚀 Launching Undetected Chrome...")
        driver = uc.Chrome(
            user_data_dir=automation_dir,
            options=options,
            use_subprocess=True,
            version_main=chrome_version
        )
        print("✅ Chrome started successfully!")
    except Exception as e:
        print(f"❌ Failed to start Chrome: {e}")
        return

    try:
        # Step 1: Open search page
        search_url = "https://medium.com/search?q=xss"
        print(f"🌐 Navigating to Medium Search: {search_url}")
        driver.get(search_url)
        time.sleep(6)  # Wait for page to initialize

        # Check for dynamic login block / interrupter (if any, wait for manual action)
        print("👀 Checking if page loaded successfully. Solve any CAPTCHAs or logins in the browser window if prompted.")
        
        # Step 2: Scroll and click "Show more" button to load more results
        load_cycles = 150  # Increased load limit to fetch more than 160 articles
        no_new_results_count = 0
        last_links_count = 0
        
        print(f"⏳ Loading search results (up to {load_cycles} scroll & click cycles)...")
        for i in range(load_cycles):
            # Scroll to the bottom to trigger dynamic loading or reveal the button
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            time.sleep(2.5)
            
            # Find and click the "Show more" button if visible
            try:
                # Case-insensitive XPath translation of text "Show more"
                show_more_buttons = driver.find_elements(By.XPATH, "//button[contains(translate(., 'SHOW MORE', 'show more'), 'show more')]")
                if show_more_buttons:
                    btn = show_more_buttons[-1]  # Select the bottom-most show more button
                    if btn.is_displayed():
                        # Scroll it to center and click via JS to bypass click intercepts
                        driver.execute_script("arguments[0].scrollIntoView({behavior: 'smooth', block: 'center'});", btn)
                        time.sleep(1.0)
                        driver.execute_script("arguments[0].click();", btn)
                        print(f"   Cycle {i + 1}/{load_cycles}: Clicked 'Show more' button.")
                        time.sleep(2.0)
                    else:
                        print(f"   Cycle {i + 1}/{load_cycles}: scrolled to bottom (button not active/displayed yet).")
                else:
                    print(f"   Cycle {i + 1}/{load_cycles}: scrolled to bottom.")
            except Exception as click_err:
                print(f"   Cycle {i + 1}/{load_cycles}: scroll completed, 'Show more' click error: {click_err}")
            
            # Auto-stop checking logic to avoid unnecessary cycles once we hit the end
            try:
                current_links = driver.find_elements(By.TAG_NAME, "a")
                current_count = len(current_links)
                if current_count == last_links_count and last_links_count > 0:
                    no_new_results_count += 1
                    if no_new_results_count >= 5:
                        print("\nℹ️ No new content detected on page for 5 consecutive cycles. We have reached the end of search results.")
                        break
                else:
                    no_new_results_count = 0
                last_links_count = current_count
            except:
                pass
        print("\n✅ Results loading sequence completed.")

        # Step 3: Extract URLs using robust Medium regex matching base16/hex hashes at the end of post links
        print("🔗 Scanning page for article links...")
        links_elements = driver.find_elements(By.TAG_NAME, "a")
        article_links = []
        seen_urls = set()

        # Regex to match article paths ending with a Medium post hash (8 to 15 hex/alphanumeric characters)
        # e.g., ...some-title-67c295b9d3b
        article_hash_pattern = re.compile(r'-[a-zA-Z0-9]{8,15}(?:\?.*)?$')

        for elem in links_elements:
            try:
                href = elem.get_attribute("href")
                if not href:
                    continue
                
                # Strip query params to normalize
                normalized_href = href.split('?')[0]
                
                # Check if it has a post hash and isn't a known layout/system link
                if article_hash_pattern.search(normalized_href):
                    if not any(k in normalized_href for k in ["/search", "/tag", "/me/", "/topics", "/about", "/policy", "/membership"]):
                        # Exclude user profiles ending with a hash
                        if not re.search(r'@[\w.-]+/?$', normalized_href):
                            if normalized_href not in seen_urls:
                                seen_urls.add(normalized_href)
                                
                                # Try to get the text of the link/element as a title fallback
                                title_text = elem.text.strip()
                                article_links.append({"url": href, "title": title_text})
            except:
                continue

        total_found = len(article_links)
        print(f"🎉 Identified {total_found} unique XSS writeup links.")

        if total_found == 0:
            print("⚠️ No article URLs detected. Ensure you are logged in or solve any browser challenges.")
            return

        # Step 4: Visit each article and convert to Markdown
        skipped_count = 0
        for index, item in enumerate(article_links):
            url = item["url"]
            normalized_url = url.split('?')[0]
            
            if normalized_url in scraped_urls:
                skipped_count += 1
                continue
                
            suggested_title = item["title"] or f"writeup_{index + 1}"
            
            print(f"📖 [{index + 1}/{total_found}] Scraping article: {url}")
            try:
                driver.get(url)
                time.sleep(4.5)  # Wait for content to render
                
                # Extract markdown directly inside the browser using JavaScript
                markdown_content = driver.execute_script(convert_to_markdown_js())
                
                if not markdown_content:
                    print(f"   ⚠️ Could not extract content (DOM mismatch or paywall/membership block).")
                    continue
                
                # Extract actual title from page
                actual_title = suggested_title
                try:
                    title_el = driver.find_element(By.TAG_NAME, "h1")
                    if title_el and title_el.text.strip():
                        actual_title = title_el.text.strip()
                except:
                    pass
                
                filename = clean_filename(actual_title)
                if not filename:
                    filename = f"writeup_{index + 1}"
                
                # Append original URL for reference
                markdown_content += f"\n\n---\n*Original URL: [{url}]({url})*\n"
                
                file_path = os.path.join(output_dir, f"{filename}.md")
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(markdown_content)
                print(f"   💾 Saved as: {filename}.md")
                
                # Update progress history file
                with open(scraped_history_file, "a", encoding="utf-8") as history_f:
                    history_f.write(normalized_url + "\n")
                scraped_urls.add(normalized_url)
                
                # Simple cooldown delay
                time.sleep(3)
                
            except Exception as scrape_err:
                print(f"   ❌ Error scraping: {scrape_err}")
                continue

        if skipped_count > 0:
            print(f"⏭️ Skipped {skipped_count} previously scraped article(s).")
        print(f"\n✨ Scraping completed! Output files are located in: {output_dir}")

    except KeyboardInterrupt:
        print("\n👋 Process stopped by user.")
    finally:
        try:
            driver.quit()
        except:
            pass

if __name__ == "__main__":
    main()
