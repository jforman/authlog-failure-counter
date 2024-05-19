#!/usr/bin/env python3
""" Parse OpenBSD authlog for failed SSH attempts and write a pf-compatible file with IPs to block."""

from collections import Counter
import argparse
import datetime
import ipaddress
import logging
import os
import pprint
import re
import sys


# These two regexes come up with the same results. Let's keep them both in
# for now, since I'm not convinced there might be some difference.
# "Failed password for invalid user ec2-user from 68.183.10.68 port 47968 ssh2"
FAILED_PASSWORD_INVALID_USER_RE=re.compile(r".*Failed password for invalid user (?P<username>\S+) from (?P<sourceAddress>\S+).*")
# "Invalid user administrator from 119.28.77.167 port 57292"
INVALID_USER_RE=re.compile(r".*Invalid user (?P<username>\S+) from (?P<sourceAddress>\S+).*")

#  Failed password for root from 218.92.0.100 port 35332 ssh2
FAILED_PASSWORD_RE=re.compile(r".*Failed password for (?P<username>\S+) from (?P<sourceAddress>\S+).*")

loginFailureCounter = Counter()

def incrementCount(source_address, ignore_ipnetworks, ignore_addressfamily):
    """given a dict and username source, increment the counter."""
    if not ignoreIPAddress(source_address, ignore_ipnetworks, ignore_addressfamily):
        logging.debug(f"Incrementing counter for {source_address}.")
        loginFailureCounter[source_address] += 1

def ignoreIPAddress(ip, ignore_ipnetworks, ignore_addressfamily):
    """If ip is in ignore_ipnetworks, return true."""
    ip = ipaddress.ip_address(ip)
    logging.debug(f"Checking if {ip} is on any ignore lists.")

    if isinstance(ip, ipaddress.IPv4Address):
        if 'ipv4' in ignore_addressfamily:
            return True
        for current_block in ignore_ipnetworks:
            logging.debug(f"Current block: {current_block}")
            if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(current_block):
                logging.debug(f"IPv4 address {ip} found in ignore list.")
                return True
        return False

    if isinstance(ip, ipaddress.IPv6Address):
        if 'ipv6' in ignore_addressfamily:
            return True
        for current_block in ignore_ipnetworks:
            if ipaddress.IPv4Address(ip) in ipaddress.IPv6Network(current_block):
                logging.debug(f"IPv6 address {ip} found in ignore list.")
                return True
        return False

    logging.info(f"Unable to determine IP version of IP: {ip}. Failing closed.")
    return False

def processLine(line):
    logging.debug(f"Processing line: {line}.")
    if FAILED_PASSWORD_INVALID_USER_RE.match(line):
        m = FAILED_PASSWORD_INVALID_USER_RE.match(line)
        logging.debug(f"Matched FAILED_PASSWORD_INVALID_USER_RE: username: {m.group('username')}, sourceAddress: {m.group('sourceAddress')}.")
        return m.group('sourceAddress')
    if INVALID_USER_RE.match(line):
        m = INVALID_USER_RE.match(line)
        logging.debug(f"Matched INVALID_USER_RE: username: {m.group('username')}, sourceAddress: {m.group('sourceAddress')}.")
        return m.group('sourceAddress')
    if FAILED_PASSWORD_RE.match(line):
        m = FAILED_PASSWORD_RE.match(line)
        logging.debug(f"Matched INVALID_USER_RE: username: {m.group('username')}, sourceAddress: {m.group('sourceAddress')}.")
        return m.group('sourceAddress')
    return None

def processLogFile(authlog, ignore_ipnetworks, ignore_addressfamily):
    """Given a filename, parse it line by line."""
    with open(authlog) as f:
        for logline in f:
            logline = logline.strip()
            ipAddress = processLine(logline)
            if ipAddress:
                incrementCount(ipAddress, ignore_ipnetworks, ignore_addressfamily)

def writeIPBlockFiles(output_dir, min_attempts):
    """write out the ip block files with occurances notes."""
    write_timestamp=datetime.datetime.now()
    with open(f"{output_dir}/failed_logins.pf", "w") as data:
        data.write(f"# Update time: {write_timestamp} UTC\n")
        for k, v in sorted(loginFailureCounter.items()):
            if v >= min_attempts:
                data.write(f"# Occurances: {v}\n")
                data.write(f"{k}\n")

def main():
    parser = argparse.ArgumentParser(description='Process log file and spit out PF-compatible block files.')
    parser.add_argument('--authlog', help='openbsd authlog file path.', default='/var/log/authlog')
    parser.add_argument('--min_attempts', type=int, help='minimum number of failed login attemps before adding IP to blocklist.', default=1)
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--output_dir', help='directory in which to write ip block files.')
    parser.add_argument('--ignore_ipnetworks', action='append', help="IP network to ignore when deciding whether to add to the block list.", default=[])
    parser.add_argument('--ignore_addressfamily', choices=['ipv4', 'ipv6'], default=[])
    args = parser.parse_args()

    if args.debug:
            logging_level=logging.DEBUG
    else:
            logging_level=logging.INFO
    logging.basicConfig(stream=sys.stdout, level=logging_level)
    logging.info(f'Starting to process {args.authlog}.')

    if args.output_dir and not os.path.exists(args.output_dir):
        logging.fatal(f'output dir {args.output_dir} does not exist.')
        sys.exit(1)

    processLogFile(args.authlog, args.ignore_ipnetworks, args.ignore_addressfamily)

    if args.output_dir:
        writeIPBlockFiles(args.output_dir, args.min_attempts)
    else:
        # TODO: add logic to only print the ones whose occurance counts are >= min attempts
        logging.info(loginFailureCounter.items())

    logging.info(f'Finished processing {args.authlog}.')

if __name__ == "__main__":
    sys.exit(main())
