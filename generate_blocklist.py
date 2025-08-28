#!/usr/bin/env python3
"""
uBlacklist Generator Script
Processes multiple source formats and generates optimized uBlacklist subscription file
"""

import re
import requests
from urllib.parse import urlparse
from collections import defaultdict
from typing import Set, List, Dict
import argparse


class DomainProcessor:
    def __init__(self):
        self.domains = set()
        self.subdomain_map = defaultdict(set)

    def extract_domain_from_hosts(self, line: str) -> str:
        """Extract domain from hosts format (0.0.0.0 example.com)"""
        parts = line.strip().split()
        if len(parts) >= 2 and (parts[0] == "0.0.0.0" or parts[0] == "127.0.0.1"):
            domain = parts[1].strip()
            # Remove any trailing comments
            domain = domain.split("#")[0].strip()
            return domain
        return None

    def normalise_domain(self, domain: str) -> str:
        """Clean and normalise domain name"""
        domain = domain.strip().lower()
        # Remove protocol if present
        domain = re.sub(r"^https?://", "", domain)
        # Remove trailing slash and path
        domain = domain.split("/")[0]
        # Remove port numbers
        domain = domain.split(":")[0]
        return domain

    def is_subdomain(self, domain: str, potential_parent: str) -> bool:
        """Check if domain is a subdomain of potential_parent"""
        if domain == potential_parent:
            return False
        return domain.endswith("." + potential_parent)

    def find_common_suffix(self, domains: List[str]) -> str:
        """Find the longest common suffix amongst domains"""
        if not domains:
            return ""

        # Split domains into parts
        domain_parts = [domain.split(".") for domain in domains]

        # Find common suffix by comparing from the end
        common_suffix = []
        min_length = min(len(parts) for parts in domain_parts)

        for i in range(1, min_length + 1):
            # Check if all domains have the same part at position -i
            parts_at_i = [parts[-i] for parts in domain_parts]
            if len(set(parts_at_i)) == 1:
                common_suffix.insert(0, parts_at_i[0])
            else:
                break

        return ".".join(common_suffix)

    def optimise_domains(self, domains: Set[str]) -> Set[str]:
        """Optimise domain list by finding common parent domains"""
        domain_list = list(domains)

        # Group domains by their root domain (last two parts typically)
        groups = defaultdict(list)
        for domain in domain_list:
            parts = domain.split(".")
            if len(parts) >= 2:
                root = ".".join(parts[-2:])  # e.g., example.com
                groups[root].append(domain)

        optimised = set()

        for root, group_domains in groups.items():
            if len(group_domains) == 1:
                optimised.add(group_domains[0])
            else:
                # Find common parent domain
                common_suffix = self.find_common_suffix(group_domains)
                if common_suffix and len(common_suffix.split(".")) >= 2:
                    # Check if using the common suffix covers all domains in the group
                    covered = all(
                        domain == common_suffix or domain.endswith("." + common_suffix)
                        for domain in group_domains
                    )
                    if covered:
                        optimised.add(common_suffix)
                    else:
                        optimised.update(group_domains)
                else:
                    optimised.update(group_domains)

        return optimised

    def format_for_ublacklist(self, domain: str) -> str:
        """Convert domain to uBlacklist format"""
        # For most domains, use wildcard subdomain format
        return f"*://*.{domain}/*"

    def process_source(self, content: str, source_type: str) -> Set[str]:
        """Process source content based on type"""
        domains = set()

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if source_type == "hosts":
                domain = self.extract_domain_from_hosts(line)
                if domain:
                    domains.add(self.normalise_domain(domain))
            elif source_type == "domain":
                domain = self.normalise_domain(line)
                if domain and "." in domain:
                    domains.add(domain)

        return domains


def fetch_source(url: str) -> str:
    """Fetch content from URL"""
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return ""


def main():
    parser = argparse.ArgumentParser(
        description="Generate uBlacklist subscription file"
    )
    parser.add_argument("--output", "-o", default="blocklist.txt", help="Output file")
    parser.add_argument(
        "--sources", required=True, help="Path to sources configuration file"
    )
    args = parser.parse_args()

    # Example sources configuration format:
    # Each line: URL,TYPE where TYPE is 'hosts' or 'domain'
    sources = []
    try:
        with open(args.sources, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split(",")
                    if len(parts) == 2:
                        sources.append((parts[0].strip(), parts[1].strip()))
    except FileNotFoundError:
        print(f"Sources file {args.sources} not found")
        return 1

    processor = DomainProcessor()
    all_domains = set()

    # Process each source
    for url, source_type in sources:
        print(f"Processing {url} ({source_type})")
        content = fetch_source(url)
        if content:
            domains = processor.process_source(content, source_type)
            all_domains.update(domains)
            print(f"  Found {len(domains)} domains")

    print(f"Total domains before optimisation: {len(all_domains)}")

    # Optimise domains
    optimised_domains = processor.optimise_domains(all_domains)
    print(f"Total domains after optimisation: {len(optimised_domains)}")

    # Convert to uBlacklist format and sort
    ublacklist_entries = []
    for domain in sorted(optimised_domains):
        ublacklist_entries.append(processor.format_for_ublacklist(domain))

    # Write output
    with open(args.output, "w") as f:
        f.write("# uBlacklist subscription file\n")
        f.write("# Generated automatically\n\n")
        for entry in ublacklist_entries:
            f.write(entry + "\n")

    print(f"Generated {args.output} with {len(ublacklist_entries)} entries")
    return 0


if __name__ == "__main__":
    exit(main())
