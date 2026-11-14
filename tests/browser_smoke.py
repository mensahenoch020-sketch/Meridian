"""Mobile banking flows against a real server; screenshots uploaded by CI."""
import os, subprocess, tempfile, time, urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

with tempfile.TemporaryDirectory() as tmp:
    env=dict(os.environ,DB_PATH=str(Path(tmp)/"bank.db"),PORT="8099")
    proc=subprocess.Popen(["python","server.py"],env=env)
    try:
        for attempt in range(60):
            try:
                urllib.request.urlopen("http://127.0.0.1:8099/health",timeout=1)
                break
            except Exception:
                time.sleep(.25)
        with sync_playwright() as p:
            browser=p.chromium.launch()
            page=browser.new_page(viewport={"width":390,"height":844},is_mobile=True,device_scale_factor=1)
            errors=[]
            page.on("pageerror",lambda error: errors.append(str(error)))
            page.goto("http://127.0.0.1:8099")
            page.get_by_label("Email address").fill("alex@meridian.demo")
            page.get_by_label("Password",exact=True).fill("MeridianDemo123!")
            page.locator("#auth-form button[type=submit]").click()
            expect(page.locator("#shell")).to_be_visible()
            expect(page.locator(".balance-value")).to_have_text("$10,000.00")
            Path("artifacts").mkdir(exist_ok=True)
            page.screenshot(path="artifacts/mobile-overview.png",full_page=True)
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"),"Page overflows mobile viewport"
            page.locator("nav [data-view=transfer]").click()
            page.get_by_label("Recipient email").fill("sam@meridian.demo")
            page.get_by_label("Amount (USD)").fill("25.50")
            page.locator("#transfer-form button").click()
            expect(page.locator("#receipt")).to_contain_text("Transfer complete")
            expect(page.locator("#transfer-available")).to_have_text("Available: $9,974.50")
            page.locator("nav [data-view=bitcoin]").click()
            page.get_by_label("Amount (BTC)").fill("0.001")
            page.locator("#trade-form button").click()
            expect(page.locator(".btc-value")).to_have_text("0.00100000 BTC")
            page.locator("#logout").click()
            page.get_by_label("Email address").fill("admin@meridian.demo")
            page.get_by_label("Password",exact=True).fill("MeridianAdmin123!")
            page.locator("#auth-form button[type=submit]").click()
            page.locator("nav [data-view=admin]").click()
            expect(page.locator("#balance-form")).to_be_visible()
            page.get_by_label("Customer",exact=True).select_option(label="Alex Morgan · alex@meridian.demo")
            page.get_by_label("New total balance").fill("15000")
            page.get_by_label("Reason for adjustment").fill("Mobile integration verification")
            page.locator("#balance-form button").click()
            expect(page.locator("#current-balance")).to_have_text("Current balance: $15,000.00")
            page.screenshot(path="artifacts/mobile-admin.png",full_page=True)
            page.set_viewport_size({"width":1440,"height":1000})
            page.locator("nav [data-view=overview]").click()
            expect(page.locator(".balance-value")).to_be_visible()
            page.screenshot(path="artifacts/desktop-overview.png",full_page=True)
            page.locator("#logout").click()
            page.locator("#toggle-auth").click()
            page.get_by_label("Full name").fill("Mobile Signup")
            page.get_by_label("Email address").fill("mobile-signup@example.com")
            page.get_by_label("Password",exact=True).fill("MobileSignupPassword123!")
            page.locator("#auth-form button[type=submit]").click()
            expect(page.locator("#shell")).to_be_visible()
            expect(page.locator(".balance-value")).to_have_text("$10,000.00")
            page.locator("#logout").click()
            page.locator("#toggle-auth").click()
            page.get_by_label("Password",exact=True).fill("incorrect")
            page.locator("#auth-form button[type=submit]").click()
            expect(page.locator("#auth-error")).to_be_visible()
            assert not errors,errors
            browser.close()
    finally:
        proc.terminate()
        proc.wait(timeout=10)
