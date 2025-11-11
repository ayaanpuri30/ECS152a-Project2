#!/usr/bin/env python3
import json
import os
from pathlib import Path
from urllib.parse import urlparse

import tldextract

HAR_DIR = Path("./top100_harfiles")


# getting exact domain name for site
def registrable(hostname: str) -> str:
    if not hostname:
        return ""
    ext = tldextract.extract(hostname)
    if not ext.domain or not ext.suffix:
        return ""
    return f"{ext.domain}.{ext.suffix}"


def analyze_hars():
    per_site_requests = {}  # total # of 3rd party requests per site
    per_site_unique = {}  # set of 3rd party request domains per site
    global_counts = {}  # global third party domain count

    per_site_data = {}  # site_reg -> list of (cookie_name, cookie_owner_reg, source)
    per_site_counts = {}  # total third-party cookies per site
    cookie_name_counts = {}  # global counts by cookie name
    cookie_name_examples = {}  # cookie_name -> set of example domains that set/send it

    for file in os.listdir(HAR_DIR):
        har_path = os.path.join(HAR_DIR, file)
        base = file.replace(".har", "").strip().lower()

        # base site domain
        site_reg = registrable(base)

        if not site_reg:
            continue

        try:
            with open(har_path, "r") as fh:
                data = json.load(fh)
        except Exception as e:
            print(f"Skipping {file}: failed to read/parse HAR ({e})")
            continue

        entries = data["log"]["entries"]
        for entry in entries:
            try:
                url = entry["request"]["url"]
                resp_cookies = entry["response"]["cookies"]
                req_cookies = entry["request"]["cookies"]

                parsed = urlparse(url)

                # request base domain
                req_reg = registrable(parsed.hostname)

                for c in resp_cookies:
                    name = c["name"]
                    cookie_domain_raw = c["domain"]
                    cookie_domain = cookie_domain_raw.lstrip(".").lower()
                    cookie_reg = registrable(cookie_domain)

                    if cookie_reg != site_reg and cookie_reg:
                        per_site_counts[site_reg] = per_site_counts.get(site_reg, 0) + 1

                        if site_reg in per_site_data:
                            per_site_data[site_reg].append(
                                (name, cookie_reg, "response.set-cookie")
                            )
                        else:
                            per_site_data[site_reg] = [
                                (name, cookie_reg, "response.set-cookie")
                            ]

                        cookie_name_counts[name] = cookie_name_counts.get(name, 0) + 1

                        if name in cookie_name_examples:
                            cookie_name_examples[name].add(cookie_reg)
                        else:
                            cookie_name_examples[name] = set([cookie_reg])

                for c in req_cookies:
                    name = c["name"]
                    cookie_domain_raw = c["domain"]
                    cookie_domain = cookie_domain_raw.lstrip(".").lower()
                    cookie_reg = registrable(cookie_domain)

                    if cookie_reg != site_reg and cookie_reg:
                        per_site_counts[site_reg] = per_site_counts.get(site_reg, 0) + 1

                        if site_reg in per_site_data:
                            per_site_data[site_reg].append(
                                (name, cookie_reg, "request.cookie_sent")
                            )
                        else:
                            per_site_data[site_reg] = [
                                (name, cookie_reg, "request.cookie_sent")
                            ]

                        cookie_name_counts[name] = cookie_name_counts.get(name, 0) + 1

                        if name in cookie_name_examples:
                            cookie_name_examples[name].add(cookie_reg)
                        else:
                            cookie_name_examples[name] = set([cookie_reg])

                if (
                    req_reg != site_reg
                    and parsed.scheme in ("http", "https")
                    and parsed.hostname
                    and req_reg
                ):
                    per_site_requests[site_reg] = per_site_requests.get(site_reg, 0) + 1

                    if site_reg in per_site_unique:
                        per_site_unique[site_reg].add(req_reg)
                    else:
                        per_site_unique[site_reg] = set([req_reg])

                    global_counts[req_reg] = global_counts.get(req_reg, 0) + 1
            except Exception as e:
                print("Failed to determine unique domain", e)
                continue

    return (
        per_site_requests,
        per_site_unique,
        global_counts,
        per_site_data,
        per_site_counts,
        cookie_name_counts,
        cookie_name_examples,
    )


def main():
    if not os.path.exists(HAR_DIR):
        print("HAR directory not found")
        return

    (
        per_site_requests,
        per_site_unique,
        global_counts,
        per_site_data,
        per_site_counts,
        cookie_name_counts,
        cookie_name_examples,
    ) = analyze_hars()

    print("=" * 20, "Third-party requests per visited site", "=" * 20)
    for site, reqs in per_site_requests.items():
        uniques = len(per_site_unique[site])
        print(f"\t{site}: {reqs} requests to {uniques} unique third-party domains")

    print("\n" + "=" * 20, "Top 10 third-party domains (global)", "=" * 20)
    top_sites = sorted(global_counts.items(), key=lambda item: item[1], reverse=True)[
        :10
    ]
    for domain, cnt in top_sites:
        print(f"\t{domain}: {cnt}")

    print("\n" + "=" * 20, "Third-party cookies summary", "=" * 20)
    print(f"Found third-party cookie data on {len(per_site_data)} visited sites.")
    for site, data in per_site_data.items():
        print(f"\t{site}: name: {data[0]} reg: {data[1]} type: {data[2]}")

    for site, cnt in per_site_counts.items():
        print(f"\t{site}: {cnt} third party cookies per site")

    print(f"Total distinct third-party cookie names seen: {len(cookie_name_counts)}")
    top_counts = sorted(cookie_name_counts.items(), key=lambda kv: kv[1], reverse=True)[
        :20
    ]
    if len(top_counts) > 0:
        print(
            "\nTop 20 third-party cookie names (name: count, example owner domain(s))"
        )
        for name, cnt in top_counts:
            examples = ", ".join(sorted(cookie_name_examples.get(name, set()))[:5])
            print(f"\t{name}: {cnt}  (examples: {examples})")


if __name__ == "__main__":
    main()
