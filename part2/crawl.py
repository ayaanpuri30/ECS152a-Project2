import json
import os
import time

from browsermobproxy import Server
from selenium import webdriver
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.chrome.options import Options

BROWSERMOB_PATH = "/Users/vpenumarti/downloads/browsermob-proxy/bin/browsermob-proxy"
CSV_PATH = "./top-1m.csv"
OUTPUT_DIR = "./top100_harfiles"
PER_SITE_TIMEOUT_SEC = 25
EXTRA_NETWORK_IDLE_WAIT_SEC = 3
CAPTURE_BINARY_CONTENT = False
HEADLESS = False
NUM_SITES = 100


def get_top_sites():
    sites = set()
    with open(CSV_PATH, "r") as f:
        for line in f:
            _, site = line.split(",")
            sites.add(site.strip().lower())

            if len(sites) == NUM_SITES:
                break

    return sites


def wait_page_settled(driver, extra_wait=EXTRA_NETWORK_IDLE_WAIT_SEC):
    driver.execute_script("return document.readyState")
    try:
        end = time.time() + 10
        while time.time() < end:
            state = driver.execute_script("return document.readyState")
            if state == "complete":
                break
            time.sleep(0.2)
    finally:
        time.sleep(extra_wait)


def ensure_scheme(host: str) -> str:
    if not host.startswith(("http://", "https://")):
        return "https://" + host
    host.replace("http://", "https://")
    return host


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    server = Server(BROWSERMOB_PATH)
    server.start()
    try:
        proxy = server.create_proxy()
        proxy_host_port = proxy.proxy

        chrome_opts = Options()
        if HEADLESS:
            chrome_opts.add_argument("--headless=new")
        chrome_opts.add_argument(f"--proxy-server={proxy_host_port}")
        chrome_opts.add_argument("--ignore-certificate-errors")
        chrome_opts.add_argument("--disable-gpu")
        chrome_opts.add_argument("--no-sandbox")
        chrome_opts.add_argument("--disable-dev-shm-usage")

        driver = webdriver.Chrome(options=chrome_opts)
        driver.set_page_load_timeout(PER_SITE_TIMEOUT_SEC)

        try:
            sites = get_top_sites()
            print(f"Collected {len(sites)} sites from {CSV_PATH}")

            for idx, site in enumerate(sites, start=1):
                url = ensure_scheme(site)

                fname = f"{site}.har"
                out_path = os.path.join(OUTPUT_DIR, fname)

                print(f"[{idx}/{len(sites)}] Visiting: {url}")

                # Start a fresh HAR for this site
                proxy.new_har(
                    site,
                    options={
                        "captureHeaders": True,
                        "captureContent": True,
                        "captureBinaryContent": CAPTURE_BINARY_CONTENT,
                    },
                )

                # Navigate and wait
                try:
                    driver.get(url)
                    wait_page_settled(driver)
                except (TimeoutException, WebDriverException) as e:
                    try:
                        driver.get(url.replace("https://", "http://"))
                        wait_page_settled(driver)
                    except (TimeoutException, WebDriverException) as e2:
                        print(f"Navigation error for {site}: {e}, {e2}")

                # Fetch HAR and write
                try:
                    har_data = proxy.har
                    with open(out_path, "w", encoding="utf-8") as fh:
                        json.dump(har_data, fh, ensure_ascii=False, indent=2)
                    print(f"Saved HAR: {out_path}")
                except Exception as e:
                    print(f"Failed to save HAR for {site}: {e}")

            driver.quit()
            server.stop()
        except Exception:
            pass
    except Exception:
        pass


if __name__ == "__main__":
    main()
