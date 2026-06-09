import os
import asyncio
from concurrent.futures import ThreadPoolExecutor

class ScreenshotTaker:
    def __init__(self, output_dir="screenshots", timeout=30):
        self.output_dir = output_dir
        self.timeout = timeout

    def take(self, url, filename=None):
        if filename is None:
            import re
            filename = re.sub(r'[^a-zA-Z0-9]', '_', url) + ".png"
        filepath = os.path.join(self.output_dir, filename)
        os.makedirs(self.output_dir, exist_ok=True)
        try:
            import subprocess
            result = subprocess.run(
                ["node", "-e", f"""
const puppeteer = require('puppeteer');
(async () => {{
  const browser = await puppeteer.launch({{ headless: 'new' }});
  const page = await browser.newPage();
  await page.setViewport({{ width: 1280, height: 720 }});
  try {{
    await page.goto('{url}', {{ waitUntil: 'networkidle2', timeout: {self.timeout * 1000} }});
    await page.screenshot({{ path: '{filepath.replace(os.sep, '/')}', fullPage: false }});
  }} catch(e) {{}}
  await browser.close();
}})();
"""],
                capture_output=True,
                timeout=self.timeout + 10,
            )
            if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
                return filepath
        except Exception:
            pass
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page(viewport={"width": 1280, "height": 720})
                page.goto(url, timeout=self.timeout * 1000, wait_until="networkidle")
                page.screenshot(path=filepath, full_page=False)
                browser.close()
                if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
                    return filepath
        except ImportError:
            pass
        except Exception:
            pass
        return None

    def take_many(self, urls, max_workers=5):
        results = {}
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            import re
            futures = {}
            for url in urls:
                fn = re.sub(r'[^a-zA-Z0-9]', '_', url) + ".png"
                futures[executor.submit(self.take, url, fn)] = url
            from concurrent.futures import as_completed
            for f in as_completed(futures):
                url = futures[f]
                results[url] = f.result()
        return results
