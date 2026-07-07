"""Selenium browser configuration."""
import os
from typing import Dict, Any, List
from selenium.webdriver.chrome.options import Options
from backend_api.config import settings


class SeleniumConfig:
    """Configuration for Selenium browser instances."""
    
    # Chrome launch arguments mapping Playwright flags
    BROWSER_ARGS = [
        '--headless=new',
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--disable-gpu',
        '--disable-background-networking',
        '--disable-background-timer-throttling',
        '--disable-breakpad',
        '--disable-extensions',
        '--disable-renderer-backgrounding',
        '--disable-sync',
        '--metrics-recording-only',
        '--mute-audio',
        '--no-first-run',
        '--disable-web-security',
        '--disable-features=IsolateOrigins,site-per-process',
        '--disable-site-isolation-trials',
        '--ignore-certificate-errors',
        '--allow-running-insecure-content',
        '--blink-settings=imagesEnabled=false'
    ]
    
    # Viewport settings
    VIEWPORT_WIDTH = int(os.getenv("BROWSER_VIEWPORT_WIDTH", "1280"))
    VIEWPORT_HEIGHT = int(os.getenv("BROWSER_VIEWPORT_HEIGHT", "720"))
    
    # Timeout settings (seconds)
    NAVIGATION_TIMEOUT = int(os.getenv("BROWSER_NAVIGATION_TIMEOUT", "20"))
    ACTION_TIMEOUT = 10
    ORACLE_WAIT_TIMEOUT = float(os.getenv("ORACLE_WAIT_TIMEOUT", "1.25"))
    
    @staticmethod
    def get_chrome_options() -> Options:
        """Get configured Chrome options.
        
        Returns:
            Selenium Options instance
        """
        options = Options()
        for arg in SeleniumConfig.BROWSER_ARGS:
            options.add_argument(arg)
            
        options.add_argument(f"--window-size={SeleniumConfig.VIEWPORT_WIDTH},{SeleniumConfig.VIEWPORT_HEIGHT}")
        options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
        
        if settings.PROXY_URL:
            options.add_argument(f"--proxy-server={settings.PROXY_URL}")
            
        return options
