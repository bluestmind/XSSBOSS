import os
import sys
import time
import re
import json
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

def send_chatgpt_prompt(driver, prompt_text):
    """Injects and sends a prompt to ChatGPT using the methods in chatgpt_browser_automator.py."""
    print("📈 Injecting prompt into ChatGPT...")
    
    # Locate Prompt input
    selectors = ["#prompt-textarea", "div[contenteditable='true']", "textarea"]
    input_field = None
    for sel in selectors:
        try:
            input_field = driver.find_element(By.CSS_SELECTOR, sel)
            if input_field:
                break
        except:
            continue

    if not input_field:
        print("❌ Could not locate ChatGPT prompt input field.")
        return False

    # Inject text using modern high-fidelity React & Lexical/Slate State Reconciliation
    try:
        driver.execute_script("""
            var el = arguments[0];
            el.focus();
            el.innerHTML = "";
            var paragraphs = arguments[1].split('\\n');
            for (var i = 0; i < paragraphs.length; i++) {
                var p = document.createElement("p");
                p.textContent = paragraphs[i];
                el.appendChild(p);
            }
            el.dispatchEvent(new Event("input", { bubbles: true }));
            el.dispatchEvent(new Event("change", { bubbles: true }));
        """, input_field, prompt_text)
    except Exception as e:
        print(f"⚠️ Paragraph DOM injection skipped: {e}. Falling back to execCommand...")
        try:
            driver.execute_script("""
                var el = arguments[0];
                el.focus();
                document.execCommand('selectAll', false, null);
                document.execCommand('delete', false, null);
                document.execCommand('insertText', false, arguments[1]);
                el.dispatchEvent(new Event("input", { bubbles: true }));
            """, input_field, prompt_text)
        except Exception as inner_e:
            print(f"❌ Both text injection methods failed: {inner_e}")
            return False
            
    time.sleep(2.0)

    # Scroll input field into view and page to bottom
    try:
        driver.execute_script("arguments[0].scrollIntoView({behavior: 'smooth', block: 'center'});", input_field)
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
    except:
        pass

    # Click Send Button (Triple-redundancy Click Execution)
    sent = False
    for click_attempt in range(5):
        try:
            send_buttons = driver.find_elements(By.CSS_SELECTOR, "button[data-testid='send-button'], [data-testid='send-button']")
            if send_buttons:
                send_button = send_buttons[-1]
                try:
                    driver.execute_script("arguments[0].click();", send_button)
                except:
                    try:
                        send_button.click()
                    except:
                        pass
                sent = True
                break
        except:
            pass
        time.sleep(0.5)

    if not sent:
        print("⚠️ Send button disabled or missing. Falling back to direct Ctrl+Enter keys...")
        try:
            input_field.send_keys(Keys.CONTROL, Keys.ENTER)
            sent = True
        except:
            try:
                input_field.send_keys(Keys.ENTER)
                sent = True
            except:
                pass
                
    return sent

def wait_for_chatgpt_response(driver):
    """Waits for ChatGPT to complete response generation by monitoring the DOM and output growth."""
    print("⌛ Waiting for ChatGPT to complete response generation...")
    time.sleep(3)  # Initial buffer to let generation start
    
    generation_completed = False
    previous_text = ""
    no_change_count = 0
    
    for attempt in range(480):  # Poll up to 480 times (8 minutes max for large/slow web searches)
        try:
            # Tiered fail-safe selectors to guarantee message detection
            message_blocks = driver.find_elements(By.CSS_SELECTOR, "div[data-message-author-role='assistant'] .markdown")
            if not message_blocks:
                message_blocks = driver.find_elements(By.CSS_SELECTOR, "div[data-message-author-role='assistant']")
            if not message_blocks:
                message_blocks = driver.find_elements(By.CSS_SELECTOR, ".markdown")
            if not message_blocks:
                message_blocks = driver.find_elements(By.CSS_SELECTOR, ".prose")
            
            if message_blocks:
                current_text = driver.execute_script("return arguments[0].innerText || arguments[0].textContent || '';", message_blocks[-1])
            else:
                current_text = ""
            
            # Detect ChatGPT UI Errors (Rate limits, safety violations, generation errors)
            error_elements = driver.find_elements(By.CSS_SELECTOR, ".text-rose-500, .text-rose-600, div[class*='text-red'], div[class*='text-rose'], div[role='alert']")
            error_detected = False
            for err_el in error_elements:
                try:
                    err_text = (driver.execute_script("return arguments[0].innerText || arguments[0].textContent || '';", err_el)).strip()
                    if err_text and any(k in err_text.lower() for k in ["error", "limit", "violate", "went wrong", "try again"]):
                        print(f"\n❌ ChatGPT UI Error Detected: {err_text}")
                        error_detected = True
                        break
                except:
                    pass
            if error_detected:
                break
            
            # Self-Healing Trigger: If after 25 seconds the response hasn't started generating, re-click send
            if attempt == 25 and (not current_text or len(current_text.strip()) < 10):
                print("\n⚠️ [Self-Healing] No response started after 25s. Re-triggering send click...")
                try:
                    send_btns = driver.find_elements(By.CSS_SELECTOR, "button[data-testid='send-button'], [data-testid='send-button']")
                    if send_btns:
                        driver.execute_script("arguments[0].click();", send_btns[-1])
                except:
                    pass

            if current_text:
                print(f"⏳ Generation progress: {len(current_text)} chars captured...", end="\r", flush=True)
            
            # Check if ChatGPT is still generating, thinking, or searching
            is_generating = False
            try:
                # 1. Look for stop button (present during typing / thinking / searching)
                stop_buttons = driver.find_elements(By.CSS_SELECTOR, "button[data-testid='stop-button'], [data-testid='stop-button']")
                if stop_buttons:
                    is_generating = True
                    
                # 2. Look for active message streaming/typing indicators
                streaming = driver.find_elements(By.CSS_SELECTOR, ".result-streaming, [class*='result-streaming']")
                if streaming:
                    is_generating = True
            except:
                pass

            # If the text is non-empty and hasn't changed since the last poll
            if current_text and current_text.strip() == previous_text.strip() and len(current_text) > 5:
                if is_generating:
                    no_change_count = 0  # Force reset silence count if active indicators show generation/search is in progress
                else:
                    # Enforce a minimum wait of 30 seconds of polling to survive search/thinking pauses
                    if attempt < 30:
                        no_change_count = 0
                    else:
                        no_change_count += 1
                        # 8 consecutive seconds of silence means generation is finished
                        if no_change_count >= 8:
                            print("")  # Clear the carriage return line
                            generation_completed = True
                            break
            else:
                no_change_count = 0
                previous_text = current_text
        except Exception as e:
            pass
        time.sleep(1.0)

    if generation_completed:
        # Fetch final text
        message_blocks = driver.find_elements(By.CSS_SELECTOR, "div[data-message-author-role='assistant'] .markdown")
        if not message_blocks:
            message_blocks = driver.find_elements(By.CSS_SELECTOR, ".markdown")
        if message_blocks:
            return driver.execute_script("return arguments[0].innerText || arguments[0].textContent || '';", message_blocks[-1])
            
    return None

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    automation_dir = os.path.join(script_dir, "chatgpt_scraper_profile")
    output_dir = os.path.join(script_dir, "xss_writeups")
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"📁 Chrome Profile directory: {automation_dir}")
    print(f"📁 Output Markdown directory: {output_dir}")

    # Process cleanup
    try:
        import subprocess
        subprocess.run("taskkill /f /im chrome.exe", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run("taskkill /f /im chromedriver.exe", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as cleanup_err:
        pass

    # Ensure profile socket locks are cleaned
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
        # Navigating to ChatGPT
        chatgpt_url = "https://chatgpt.com/"
        print(f"🌐 Navigating to: {chatgpt_url}")
        driver.get(chatgpt_url)
        
        # Checking login status / waiting for text area
        is_logged_in = False
        print("🔍 Checking login state (please complete any manual login or CAPTCHA now if needed)...")
        for attempt in range(120):
            try:
                driver.find_element(By.CSS_SELECTOR, "#prompt-textarea, div[contenteditable='true']")
                is_logged_in = True
                print("✅ Logged-in session active!")
                break
            except:
                time.sleep(2)

        if not is_logged_in:
            print("❌ Timeout waiting for manual login. Exiting...")
            return

        # -------------------------------------------------------------
        # STEP 1: Ask ChatGPT to find XSS writeups on Medium
        # -------------------------------------------------------------
        search_prompt = (
            "Please use your web search tool to find the top 10 detailed XSS (Cross-Site Scripting) writeups, "
            "vulnerability reports, or walk-throughs published on Medium (medium.com). "
            "Output the results as a JSON array of objects inside a markdown code block starting with ```json and ending with ```. "
            "Each object must have exactly two keys: 'title' and 'url'. "
            "Make sure the URLs are direct links to the articles (not just search paths). Do not write any other text or description outside of the JSON block."
        )

        print("🔮 Querying ChatGPT to search for Medium writeups...")
        if not send_chatgpt_prompt(driver, search_prompt):
            print("❌ Failed to send search prompt.")
            return

        search_response = wait_for_chatgpt_response(driver)
        if not search_response:
            print("❌ Failed to get search response from ChatGPT.")
            return

        print("\n📥 Parsing search response...")
        json_match = re.search(r'```json\s*(.*?)\s*```', search_response, re.DOTALL)
        if not json_match:
            # Fallback: Try parsing any JSON-like array in the text
            json_match = re.search(r'(\[\s*\{.*\}\s*\])', search_response, re.DOTALL)
            
        if not json_match:
            print("❌ ChatGPT did not return a valid JSON block. Response was:")
            print(search_response)
            return

        try:
            articles = json.loads(json_match.group(1).strip())
        except Exception as json_err:
            print(f"❌ Failed to parse JSON: {json_err}")
            print("Response fragment:")
            print(json_match.group(1))
            return

        print(f"🎉 Successfully retrieved {len(articles)} writeups from ChatGPT!")
        for idx, art in enumerate(articles):
            print(f"   [{idx + 1}] {art.get('title')} -> {art.get('url')}")

        # -------------------------------------------------------------
        # STEP 2: Iterate over each writeup and retrieve the content
        # -------------------------------------------------------------
        for index, article in enumerate(articles):
            title = article.get("title", f"writeup_{index+1}")
            url = article.get("url")
            
            if not url:
                continue

            filename = clean_filename(title)
            if not filename:
                filename = f"writeup_{index+1}"

            print(f"\n📖 [{index + 1}/{len(articles)}] Scraping via ChatGPT: {title}")
            
            article_prompt = (
                f"Please search/visit this exact article: '{url}'\n"
                "Extract its entire technical content: Title, Author, Date, headings, paragraphs, step-by-step walkthroughs, "
                "vulnerability details, code blocks, screenshots/image descriptions, and payloads.\n"
                "Reconstruct the article fully in beautiful, detailed Markdown format. "
                "Do not summarize it; write down the complete walkthrough so I have the full reference offline. "
                "Begin the markdown document with the title as an H1, and end with the original URL citation."
            )

            if not send_chatgpt_prompt(driver, article_prompt):
                print(f"   ❌ Failed to send request for: {title}")
                continue

            article_response = wait_for_chatgpt_response(driver)
            if not article_response:
                print(f"   ❌ Failed to get article content for: {title}")
                continue

            # Save to file
            file_path = os.path.join(output_dir, f"{filename}.md")
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(article_response)
            print(f"   💾 Saved to: {filename}.md")
            
            # Simple cooling sleep to look natural
            time.sleep(5)

        print(f"\n✨ Scraper loop completed successfully! All files are in: {output_dir}")

    except KeyboardInterrupt:
        print("\n👋 Stopped by user.")
    finally:
        try:
            driver.quit()
        except:
            pass

if __name__ == "__main__":
    main()
