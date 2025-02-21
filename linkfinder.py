#!/usr/bin/env python
# Python 3
# LinkFinder
# Modified to accept a file with multiple URLs. For each URL:
#   - If the URL points directly to a .js file, process it.
#   - Otherwise, load the page, extract all JS URLs, then process each one.
#
# Output is stored in a folder "linkfinder_output", where each file is named
# after the domain (with dots replaced by underscores).
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
import ssl
import xml.etree.ElementTree as ET
from gzip import GzipFile
from string import Template
from urllib.parse import urlparse, urljoin  # For URL parsing and joining

try:
    from StringIO import StringIO
    readBytesCustom = StringIO
except ImportError:
    from io import BytesIO
    readBytesCustom = BytesIO

try:
    from urllib.request import Request, urlopen
except ImportError:
    from urllib2 import Request, urlopen

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

def parser_error(errmsg):
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
    Send HTTP request using urllib.
    """
    q = Request(url)
    q.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                               'AppleWebKit/537.36 (KHTML, like Gecko) '
                               'Chrome/58.0.3029.110 Safari/537.36')
    q.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8')
    q.add_header('Accept-Language', 'en-US,en;q=0.8')
    q.add_header('Accept-Encoding', 'gzip')
    q.add_header('Cookie', args.cookies)

    try:
        sslcontext = ssl.create_default_context()
        response = urlopen(q, timeout=args.timeout, context=sslcontext)
    except Exception as e:
        parser_error("invalid input defined or SSL error: %s" % e)

    if response.info().get('Content-Encoding') == 'gzip':
        data = GzipFile(fileobj=readBytesCustom(response.read())).read()
    elif response.info().get('Content-Encoding') == 'deflate':
        data = response.read().read()
    else:
        data = response.read()
    return data.decode('utf-8', 'replace')

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
    Check if the URL points directly to a JavaScript file.
    """
    nopelist = ["node_modules", "jquery.js"]
    if url.lower().endswith(".js"):
        parts = url.split("/")
        for part in parts:
            if part in nopelist:
                return False
        if url.startswith("//"):
            url = "https:" + url
        if not url.startswith("http"):
            # This branch may need a proper base URL; in our usage, we assume absolute URLs.
            url = args.input.rstrip("/") + "/" + url
        return url
    else:
        return False

def extract_js_urls(html_content, base_url):
    """
    Extract JavaScript URLs from HTML content using <script> tags.
    """
    js_urls = []
    # This regex finds src attributes from script tags.
    pattern = r'<script[^>]+src=["\'](.*?)["\']'
    matches = re.findall(pattern, html_content, re.IGNORECASE)
    for src in matches:
        full_url = urljoin(base_url, src)
        if full_url.lower().endswith(".js"):
            js_urls.append(full_url)
    return list(set(js_urls))

def save_links(domain, links):
    """
    Save found links to a file in the linkfinder_output folder.
    The file is named after the domain, with dots replaced by underscores.
    """
    output_folder = "linkfinder_output"
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    domain_filename = domain.replace(".", "_")
    output_file = os.path.join(output_folder, domain_filename + ".txt")
    with open(output_file, "a") as f:
        for link in links:
            f.write(link + "\n")
    print("Saved %d links for domain %s in %s" % (len(links), domain, output_file))

def process_js_url(js_url):
    """
    Process a JavaScript URL: download its content and extract endpoints.
    Returns a list of found links.
    """
    print("Processing JS file: %s" % js_url)
    try:
        file_content = send_request(js_url)
    except Exception as e:
        print("Error fetching %s: %s" % (js_url, e))
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
    default_timeout = 10
    parser.add_argument("-t", "--timeout",
                        help="Seconds to wait for the server to send data (default: " + str(default_timeout) + ")",
                        default=default_timeout, type=int, metavar="<seconds>")
    args = parser.parse_args()

    urls = parser_input(args.input)
    for url in urls:
        url = url.strip()
        if not url:
            continue

        # Determine if the URL points directly to a JS file.
        valid_js_url = check_url(url)
        js_urls = []
        if valid_js_url:
            js_urls.append(valid_js_url)
        else:
            # Not a direct JS file, assume it's an HTML page.
            print("Loading HTML page: %s" % url)
            try:
                html_content = send_request(url)
            except Exception as e:
                print("Error fetching HTML page %s: %s" % (url, e))
                continue
            js_urls = extract_js_urls(html_content, url)
            if not js_urls:
                print("No JavaScript files found on %s" % url)
                continue

        # For each JS URL found, process it.
        all_links = []
        for js_url in js_urls:
            links = process_js_url(js_url)
            all_links.extend(links)

        if all_links:
            parsed = urlparse(url)
            domain = parsed.netloc if parsed.netloc else "unknown"
            save_links(domain, all_links)
        else:
            print("No endpoints found for %s" % url)

if __name__ == "__main__":
    main()
