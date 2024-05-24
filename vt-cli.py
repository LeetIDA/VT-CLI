#!/usr/bin/env python

import argparse
import hashlib
import os
import sys
import textwrap

import vt
from colorama import Fore, init
from dotenv import load_dotenv
from prettytable import PrettyTable

"""
========================================
VT-CLI
Author: Isa Ebrahim(0xRar) -- 0xrar.net
Copyright © 2022 - 2024 
========================================
"""

# Formatting variables
init(autoreset=True)
dashes = "-" * 30
b = Fore.BLUE
c = Fore.CYAN
w = Fore.WHITE
g = Fore.GREEN
y = Fore.YELLOW
r = Fore.RED

completed = g + "[+] Analysis Completed\n"
url_err = r + "[-] expected a url, something went wrong please try again.\n"
hash_err = r + "[-] expected a [SHA-256, SHA-1 or MD5] hash, something went wrong please try again.\n"
file_hash_err = r + "[-] expected a path/to/file, something went wrong please try again.\n"


def banner():
    ascii = textwrap.dedent("""
    {}__      _________      _____ _      _____ 
    {}\ \    / /__   __|    / ____| |    |_   _|
    {} \ \  / /   | |______| |    | |      | |  
    {}  \ \/ /    | |______| |    | |      | |  
    {}   \  /     | |      | |____| |____ _| |_ 
    {}    \/      |_|       \_____|______|_____|

    {}\t\t\t By Isa Ebrahim - 0xRar
    {}
    """)
    print(ascii.format(b, b, w, w, b, b, c, w))


def url_output(url, url_obj):
    table = PrettyTable()
    table.field_names = ["Attribute", "Value"]
    table.align = "l"
    table.add_row(["First Submission Date", url_obj.first_submission_date])
    table.add_row(["Last Submission Date", url_obj.last_submission_date])
    table.add_row(["Times Submitted", url_obj.times_submitted])
    table.add_row(["Content Length", f"{url_obj.last_http_response_content_length} Bytes"])
    table.add_row(["Response Code", url_obj.last_http_response_code])
    stats = url_obj.last_analysis_stats
    stats_str = f"Malicious: {stats['malicious']}, Suspicious: {stats['suspicious']}, Harmless: {stats['harmless']}"
    table.add_row(["Stats", stats_str])
    return table


def hash_output(hash, hash_obj):
    table = PrettyTable()
    table.field_names = ["Attribute", "Value"]
    table.align = "l"
    table.add_row(["First Submission Date", hash_obj.first_submission_date])
    table.add_row(["Last Submission Date", hash_obj.last_submission_date])
    table.add_row(["Times Submitted", hash_obj.times_submitted])
    table.add_row(["File Size", f"{hash_obj.size} Bytes"])
    table.add_row(["File Type", hash_obj.type_tag])
    table.add_row(["File Type Description", hash_obj.type_description])
    stats = hash_obj.last_analysis_stats
    stats_str = f"Malicious: {stats['malicious']}, Suspicious: {stats['suspicious']}, Harmless: {stats['harmless']}"
    table.add_row(["Stats", stats_str])
    return table


def out_printer(table):
    print(table.get_string())


def url_last_analysis(url: str, client: vt.Client):
    """
    Get Information About a URL/DOMAIN
    """

    try:
        url_id = vt.url_id(url)
        url_obj = client.get_object("/urls/{}", url_id)

        table = url_output(url, url_obj)
        print(f"\nAnalysis for: {y + url + Fore.RESET}\n")
        out_printer(table)

    except:
        print(url_err)
        sys.exit("Exiting due to a wrong url.")

    else:
        print(completed)


def url_scanner(url: str, client: vt.Client):
    """
    Scans and submit url's to detect malware and other breaches.
    """

    try:
        # scan's and submit the url
        scan = client.scan_url(url, wait_for_completion=True)

        url_id = vt.url_id(url)
        url_obj = client.get_object("/urls/{}", url_id)

        table = url_output(url, url_obj)
        print(f"\nAnalysis for: {y + url + Fore.RESET}\n")
        out_printer(table)
       
    except:
        print(url_err)
        sys.exit("Exiting due to a wrong url.")

    else:
        print(completed)


def file_last_analysis(hash, client: vt.Client):
    """
    Get Information About a File Hash
    """

    try:
        hash_obj = client.get_object("/files/{}", hash)

        table = hash_output(hash, hash_obj)
        print(f"\nAnalysis for: {y + hash + Fore.RESET}\n")
        out_printer(table)
        
    except:
        print(hash_err)
        sys.exit("Exiting due to a wrong file hash type.")

    else:
        print(completed)


def file_scanner(path, client: vt.Client):
    """
    Scans/Analyze and submit file's to detect malware and other breaches.
    """

    try:
        with open(path, "rb") as f:
            if os.path.isfile(path):
                hash = hashlib.file_digest(f, "md5").hexdigest()
                client.scan_file(f)
                hash_obj = client.get_object("/files/{}", hash)

                table = hash_output(os.path.basename(path), hash_obj)
                print(f"\nAnalysis for: {y + os.path.basename(path) + Fore.RESET}\n")
                out_printer(table)
                f.close()

    except FileNotFoundError:
        print(file_hash_err)
        sys.exit("Exiting due to file not found")

    else:
        print(completed)


def main():
    """
    Main function to rule them all. ¯\_(ツ)_/¯
    """

    load_dotenv(dotenv_path="config/.env")
    token = os.getenv("VT_TOKEN")
    client = vt.Client(token)

    if args.url_analysis:  # url analysis stats
        url_last_analysis(url=args.url_analysis, client=client)

    elif args.url_scan:  # url scanner
        url_scanner(url=args.url_scan, client=client)

    elif args.file_analysis:  # file analysis stats
        file_last_analysis(hash=args.file_analysis, client=client)

    elif args.file_scan:  # file scanner
        file_scanner(path=args.file_scan, client=client)

    client.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        epilog="\tExample: \r\npython " + sys.argv[0] + " -an https://google.com/"
    )

    parser.add_argument(
        "-an",
        dest="url_analysis",
        type=str,
        help="url to get the last analysis stats",
    )

    parser.add_argument(
        "-scan",
        dest="url_scan",
        type=str,
        help="url to scan and detect malware and other breaches",
    )

    parser.add_argument(
        "-anf",
        dest="file_analysis",
        type=str,
        help="file hash[SHA-256, SHA-1, MD5] to get the last analysis stats",
    )

    parser.add_argument(
        "-scanf",
        dest="file_scan",
        help="file location to scan and detect malware and other breaches",
    )
    args = parser.parse_args()

    if len(sys.argv) < 2:
        banner()
        parser.print_usage()
        sys.exit(1)

    banner()
    main()
