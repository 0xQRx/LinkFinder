#!/usr/bin/env python
# Python 3
# LinkFinder
# Modified to accept a file with multiple URLs. For each URL:
#   - If the URL points directly to a .js file, process it.
#   - Otherwise, load the page, extract all JS URLs, then process each one.
#
# Output is stored in a directory specified by --out-dir (default: linkfinder_output),
# where each file is named after the domain (with dots replaced by underscores).
#
# By Gerben_Javado (original)
# Modified by ChatGPT

import os
import re
import sys
import glob
import html
import argparse
import jsbeautifier
import subprocess
import base64
import xml.etree.ElementTree as ET
from string import Template
from urllib.parse import urlparse, urljoin

import requests
# Suppress only the single warning from urllib3 needed.
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Regex used for extracting endpoints
regex_str = r"""
  (?:"|')                               # Start delimiter
  (
    ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme or //
    [^"'/]{1,}\.                        # Match a domainname (any char + dot)
    [a-zA-Z]{2,}[^"']{0,})              # Domain extension and/or path
    |
    ((?:/|\.\./|\./)                    # Start with /,../,./
    [^"'><,;| *()(%%$^/\\\[\]]          # Next character restrictions
    [^"'><,;|()]{1,})                   # Rest of the characters restrictions
    |
    ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
    [a-zA-Z0-9_\-/.]{1,}                # Resource name
    \.(?:[a-zA-Z]{1,4}|action)          # Extension (1-4 letters or action)
    (?:[\?|#][^"|']{0,}|))              # Optional ? or # with parameters
    |
    ([a-zA-Z0-9_\-/]{1,}/               # REST API endpoint with /
    [a-zA-Z0-9_\-/]{3,}                 # Endpoint (usually 3+ chars)
    (?:[\?|#][^"|']{0,}|))              # Optional ? or # with parameters
    |
    ([a-zA-Z0-9_\-]{1,}                 # Filename
    \.(?:php|asp|aspx|jsp|json|
         action|html|js|txt|xml)        # . + extension
    (?:[\?|#][^"|']{0,}|))              # Optional ? or # with parameters
  )
  (?:"|')                               # End delimiter
"""

context_delimiter_str = "\n"

def debug_print(message):
    if args.verbose:
        print(message)

def parser_error(errmsg):
    if args.verbose:
        print("Usage: python %s [Options] -h for help" % sys.argv[0])
        print("Error: %s" % errmsg)
    sys.exit()

def parser_input(input_str):
    """
    Parse Input.
    This function handles:
      - A single URL (starting with http://, etc.)
      - A file with multiple URLs (one per line)
      - A wildcard expression for a folder
    """
    if input_str.startswith(('http://', 'https://', 'file://', 'ftp://', 'ftps://')):
        return [input_str]

    if "*" in input_str:
        paths = glob.glob(os.path.abspath(input_str))
        file_paths = [p for p in paths if os.path.isfile(p)]
        if not file_paths:
            parser_error("Input with wildcard does not match any files.")
        return ["file://%s" % path for path in file_paths]

    if os.path.exists(input_str):
        urls = []
        with open(input_str, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)
        if urls:
            return urls
        else:
            parser_error("The input file is empty or does not contain valid URLs.")
    
    parser_error("Input is not a valid URL or file.")
    return []

def send_request(url):
    """
    Send HTTP request using the requests library.
    SSL certificate verification is disabled.
    Returns the response text or None on errors.
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/58.0.3029.110 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.8',
        'Accept-Encoding': 'gzip',
        'Cookie': args.cookies
    }
    try:
        # Using verify=False to bypass SSL certificate verification.
        response = requests.get(url, headers=headers, timeout=args.timeout, verify=False)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        debug_print("Error fetching %s: %s" % (url, e))
        return None

def getContext(list_matches, content, include_delimiter=0, context_delimiter_str="\n"):
    """
    Extract context surrounding each regex match.
    """
    items = []
    for m in list_matches:
        match_str = m[0]
        match_start = m[1]
        match_end = m[2]
        context_start_index = match_start
        context_end_index = match_end
        delimiter_len = len(context_delimiter_str)
        content_max_index = len(content) - 1

        while context_start_index > 0 and content[context_start_index] != context_delimiter_str:
            context_start_index -= 1

        while context_end_index < content_max_index and content[context_end_index] != context_delimiter_str:
            context_end_index += 1

        if include_delimiter:
            context = content[context_start_index: context_end_index]
        else:
            context = content[context_start_index + delimiter_len: context_end_index]

        items.append({"link": match_str, "context": context})
    return items

def parser_file(content, regex_str, mode=1, more_regex=None, no_dup=1):
    """
    Use regex to extract endpoints from content.
    """
    if mode == 1:
        if len(content) > 1000000:
            content = content.replace(";", ";\r\n").replace(",", ",\r\n")
        else:
            content = jsbeautifier.beautify(content)

    regex = re.compile(regex_str, re.VERBOSE)
    if mode == 1:
        all_matches = [(m.group(1), m.start(0), m.end(0)) for m in re.finditer(regex, content)]
        items = getContext(all_matches, content, context_delimiter_str=context_delimiter_str)
    else:
        items = [{"link": m.group(1)} for m in re.finditer(regex, content)]

    if no_dup:
        seen = set()
        no_dup_items = []
        for item in items:
            if item["link"] not in seen:
                seen.add(item["link"])
                no_dup_items.append(item)
        items = no_dup_items

    if more_regex:
        items = [item for item in items if re.search(more_regex, item["link"])]

    return items

def check_url(url):
    """
    Check if the URL points directly to a JavaScript file by examining
    its path component. Returns the URL if valid, or False otherwise.
    """
    from urllib.parse import urlparse  # ensure it's imported
    parsed = urlparse(url)
    path = parsed.path
    nopelist = ["node_modules", "jquery.js"]
    if path.lower().endswith(".js"):
        # Check that none of the path segments are in the no-list.
        for part in path.split("/"):
            if part in nopelist:
                return False
        # If the URL starts with '//' prepend 'https:'
        if url.startswith("//"):
            url = "https:" + url
        # If it doesn't start with http, assume it's relative and prepend the base.
        if not url.startswith("http"):
            url = args.input.rstrip("/") + "/" + url
        return url
    else:
        return False

def extract_js_urls(html_content, base_url):
    """
    Extract JavaScript URLs from HTML content using <script> tags.
    """
    js_urls = []
    pattern = r'<script[^>]+src=["\'](.*?)["\']'
    matches = re.findall(pattern, html_content, re.IGNORECASE)
    for src in matches:
        full_url = urljoin(base_url, src)
        if full_url.lower().endswith(".js"):
            js_urls.append(full_url)
    return list(set(js_urls))

def save_links(domain, links):
    """
    Save found links to a file in the output directory.
    The file is named after the domain, with dots replaced by underscores.
    """
    output_folder = args.out_dir
    if not os.path.exists(output_folder):
        try:
            os.makedirs(output_folder)
        except Exception as e:
            debug_print("Error creating output directory %s: %s" % (output_folder, e))
            return
    domain_filename = domain.replace(".", "_")
    output_file = os.path.join(output_folder, domain_filename + ".txt")
    try:
        with open(output_file, "a") as f:
            for link in links:
                f.write(link + "\n")
        debug_print("Saved %d links for domain %s in %s" % (len(links), domain, output_file))
    except Exception as e:
        debug_print("Error writing to file %s: %s" % (output_file, e))

def process_js_url(js_url):
    """
    Process a JavaScript URL: download its content and extract endpoints.
    Returns a list of found links.
    """
    debug_print("Processing JS file: %s" % js_url)
    file_content = send_request(js_url)
    if file_content is None:
        return []
    endpoints = parser_file(file_content, regex_str, mode=1, more_regex=args.regex)
    links = [item["link"] for item in endpoints]
    return links

def main():
    global args
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input",
                        help="Input a URL or a file containing multiple URLs (one per line).",
                        required=True, action="store")
    parser.add_argument("-r", "--regex",
                        help="RegEx for filtering purposes against found endpoint (e.g. ^/api/)",
                        action="store")
    parser.add_argument("-c", "--cookies",
                        help="Add cookies for authenticated JS files",
                        action="store", default="")
    parser.add_argument("-t", "--timeout",
                        help="Seconds to wait for the server to send data (default: 10)",
                        default=10, type=int, metavar="<seconds>")
    parser.add_argument("--out-dir",
                        help="Directory to save output files (default: linkfinder_output)",
                        default="linkfinder_output", type=str)
    parser.add_argument("-v", "--verbose",
                        help="Enable verbose output", action="store_true")
    args = parser.parse_args()

    urls = parser_input(args.input)
    for url in urls:
        url = url.strip()
        if not url:
            continue

        valid_js_url = check_url(url)
        js_urls = []
        if valid_js_url:
            js_urls.append(valid_js_url)
        else:
            debug_print("Loading HTML page: %s" % url)
            html_content = send_request(url)
            if html_content is None:
                debug_print("Skipping %s due to previous errors." % url)
                continue
            js_urls = extract_js_urls(html_content, url)
            if not js_urls:
                debug_print("No JavaScript files found on %s" % url)
                continue

        all_links = []
        for js_url in js_urls:
            links = process_js_url(js_url)
            all_links.extend(links)

        if all_links:
            parsed = urlparse(url)
            domain = parsed.netloc if parsed.netloc else "unknown"
            save_links(domain, all_links)
        else:
            debug_print("No endpoints found for %s" % url)

if __name__ == "__main__":
    main()
