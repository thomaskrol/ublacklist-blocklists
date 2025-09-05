#!/usr/bin/env python3
"""
uBlacklist Multi-Category Generator Script
Processes multiple categories with metadata headers
"""

import re
import requests
import json
import yaml
from urllib.parse import urlparse
from collections import defaultdict
from typing import Set, List, Dict, Optional
from datetime import datetime, timezone
import argparse
import os
from pathlib import Path


class CategoryConfig:
    def __init__(self, config_path: str):
        with open(config_path, "r") as f:
            if config_path.endswith(".json"):
                self.config = json.load(f)
            else:  # YAML
                self.config = yaml.safe_load(f)

    @property
    def metadata(self) -> Dict:
        return self.config.get("metadata", {})

    @property
    def sources(self) -> List[Dict]:
        return self.config.get("sources", [])

    @property
    def whitelist(self) -> List[Dict]:
        return self.config.get("whitelist", [])

    @property
    def manual_entries(self) -> List[Dict]:
        return self.config.get("manual_entries", [])


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


def generate_header(config: CategoryConfig, entry_count: int, repo_info: Dict) -> str:
    """Generate the blocklist header with metadata"""
    metadata = config.metadata
    now = datetime.now(timezone.utc).isoformat()

    # YAML front matter
    header = "---\n"
    header += f"name: {metadata.get('name', 'uBlacklist blocklist')}\n"
    header += f"description: {metadata.get('description', 'A uBlacklist blocklist')}\n"
    header += f"home: {repo_info.get('home', 'https://github.com/user/repo')}\n"
    header += "---\n\n"

    # Comments section
    header += f"# report a false positive:  {repo_info.get('issues', 'https://github.com/user/repo/issues')}\n"
    header += f"# author:                   {metadata.get('author', 'Unknown')}\n"
    header += f"# url:                      {repo_info.get('raw_url', '')}\n"
    header += f"# licence:                  {metadata.get('license', 'MIT')}\n"
    header += f"# entries:                  {entry_count:,}\n"
    header += (
        f"# update frequency:         {metadata.get('update_frequency', '1 day')}\n"
    )
    header += f"# last modified:            {now}\n"
    header += "# sources (re-formatted for uBlacklist):\n"

    for source in config.sources:
        name = source.get("name", source["url"])
        url = source["url"]
        header += f"#   {name}: {url}\n"

    header += "\n"
    return header


def process_category(category_path: str, output_path: str, repo_info: Dict) -> int:
    """Process a single category"""
    print(f"Processing category: {category_path}")

    config = CategoryConfig(category_path)
    processor = DomainProcessor()
    all_domains = set()

    # Process automated sources
    for source in config.sources:
        url = source["url"]
        source_type = source["type"]
        name = source.get("name", url)

        print(f"  Processing {name} ({source_type})")
        content = fetch_source(url)
        if content:
            domains = processor.process_source(content, source_type)
            all_domains.update(domains)
            print(f"    Found {len(domains)} domains")

    # Add manual entries
    manual_entries = set()
    for entry in config.manual_entries:
        normalised = processor.normalise_domain(entry)
        if normalised and "." in normalised:
            manual_entries.add(normalised)

    if manual_entries:
        all_domains.update(manual_entries)
        print(f"  Added {len(manual_entries)} manual entries")

    print(f"  Total domains before whitelist: {len(all_domains)}")

    # Apply whitelist
    whitelist = set(config.whitelist)
    if whitelist:
        print(f"  Applying whitelist with {len(whitelist)} entries")
        all_domains = processor.apply_whitelist(all_domains, whitelist)
        print(f"  Total domains after whitelist: {len(all_domains)}")

    print(f"  Total domains before optimisation: {len(all_domains)}")

    # Optimise domains
    optimised_domains = processor.optimise_domains(all_domains)
    print(f"  Total domains after optimisation: {len(optimised_domains)}")

    # Convert to uBlacklist format and sort
    ublacklist_entries = []
    for domain in sorted(optimised_domains):
        ublacklist_entries.append(processor.format_for_ublacklist(domain))

    # Generate header
    header = generate_header(config, len(ublacklist_entries), repo_info)

    # Write output
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        f.write(header)
        for entry in ublacklist_entries:
            f.write(entry + "\n")

    print(f"  Generated {output_path} with {len(ublacklist_entries)} entries")
    return len(ublacklist_entries)


def main():
    parser = argparse.ArgumentParser(
        description="Generate uBlacklist subscription files"
    )
    parser.add_argument(
        "--config", default="repo-config.yml", help="Repository configuration file"
    )
    args = parser.parse_args()

    # Load repository configuration
    with open(args.config, "r") as f:
        repo_config = yaml.safe_load(f)

    total_entries = 0

    # Process each category
    for category in repo_config["categories"]:
        config_path = category["config"]
        output_path = category["output"]

        # Build repo info for this category
        repo_info = {
            "home": repo_config.get("home", ""),
            "issues": repo_config.get("issues", ""),
            "raw_url": f"{repo_config.get('raw_base', '')}/{output_path}",
        }

        entries = process_category(config_path, output_path, repo_info)
        total_entries += entries

    print(
        f"\nGenerated {len(repo_config['categories'])} categories with {total_entries:,} total entries"
    )
    return 0


if __name__ == "__main__":
    exit(main())
