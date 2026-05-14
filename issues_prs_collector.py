#
# Copyright (c) nexB Inc. and others. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import hashlib
import json
import os
import re
import sys
from abc import abstractmethod
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import gitlab
from aboutcode.pipeline import BasePipeline, LoopProgress
from dotenv import load_dotenv
from github import Github
from packageurl.contrib.url2purl import url2purl

load_dotenv()


class VCSCollector(BasePipeline):
    """
    Pipeline to collect GitHub/GitLab issues and PRs related to vulnerabilities.
    """

    vcs_url: str
    CVE_PATTERN = re.compile(r"(CVE-\d{4}-\d+)", re.IGNORECASE)
    SUPPORTED_IDENTIFIERS = ["CVE-"]

    def __init__(self, vcs_url: str, purl, *args, **kwargs):
        self.vcs_url = vcs_url
        self.purl = purl
        self.repo_name = f"{self.purl.namespace}/{self.purl.name}"
        self.collected_items = {
            "vcs_url": self.vcs_url,
            "vulnerabilities": defaultdict(lambda: {"Issues": [], "PRs": []}),
        }
        super().__init__(*args, **kwargs)

    @classmethod
    def steps(cls):
        return (
            cls.fetch_entries,
            cls.collect_items,
            cls.store_items,
        )

    def log(self, message):
        now_local = datetime.now(timezone.utc).astimezone()
        timestamp = now_local.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        message = f"{timestamp} {message}"
        print(message)

    @abstractmethod
    def fetch_entries(self):
        raise NotImplementedError

    @abstractmethod
    def collect_items(self):
        raise NotImplementedError

    def store_items(self):
        self.log("Storing collected Issues and PRs commit results")
        if not self.collected_items.get("vulnerabilities"):
            self.log("No collected Issues and PRs results")
            return

        vcs_url_hash = hashlib.sha256(self.vcs_url.encode("utf-8")).hexdigest()[:8]
        path = Path(f"data/issues-prs/{self.purl.name}-{vcs_url_hash}.json")

        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.collected_items, f, indent=2)


class GitLabCollector(VCSCollector):
    def fetch_entries(self):
        """Fetch Gitlab Data Entries"""
        gitlab_token = os.getenv("GLAB_API_TOKEN")

        if not gitlab_token:
            raise ValueError("GLAB_API_TOKEN environment variable not set properly")

        gl = gitlab.Gitlab("https://gitlab.com/", private_token=gitlab_token)
        project = gl.projects.get(self.repo_name)
        base_query = " ".join(self.SUPPORTED_IDENTIFIERS)
        self.issues = project.search(scope="issues", search=base_query, iterator=True)
        self.prs = project.search(
            scope="merge_requests", search=base_query, iterator=True
        )

    def collect_items(self):
        for i_type, items in [("Issues", self.issues), ("PRs", self.prs)]:
            for item in items:
                title = item.get("title") or ""
                description = item.get("description") or ""
                matches = self.CVE_PATTERN.findall(title + " " + description)
                seen_urls = set()
                for match in matches:
                    cve_id = match.upper()
                    url = item.get("web_url")
                    if not url or url in seen_urls:
                        continue

                    self.collected_items["vulnerabilities"][cve_id][i_type].append(url)
                    seen_urls.add(url)


class GitHubCollector(VCSCollector):
    def fetch_entries(self):
        """Fetch GitHub Data Entries"""
        github_token = os.getenv("GH_API_TOKEN")
        if not github_token:
            raise ValueError("GH_API_TOKEN environment variable not set properly")

        g = Github(login_or_token=github_token)
        base_query = (
            f"repo:{self.repo_name} ({' OR '.join(self.SUPPORTED_IDENTIFIERS)})"
        )
        self.issues = g.search_issues(f"{base_query} is:issue")
        self.prs = g.search_issues(f"{base_query} is:pr")

    def collect_items(self):
        for i_type, items in [("Issues", self.issues), ("PRs", self.prs)]:
            for item in items:
                matches = self.CVE_PATTERN.findall(item.title + " " + (item.body or ""))
                seen_urls = set()
                for match in matches:
                    cve_id = match.upper()
                    if not item.html_url or item.html_url in seen_urls:
                        continue
                    self.collected_items["vulnerabilities"][cve_id][i_type].append(
                        item.html_url
                    )
                    seen_urls.add(item.html_url)


if __name__ == "__main__":
    with open("config/issues_prs_targets.json") as f:
        vcs_urls = json.load(f)

    progress = LoopProgress(
        total_iterations=len(vcs_urls),
        logger=print,
    )
    for vcs_url in progress.iter(vcs_urls):
        purl = url2purl(vcs_url)
        purl_type = purl.type

        if purl_type == "gitlab":
            collector = GitLabCollector(vcs_url=vcs_url, purl=purl)
        elif purl_type == "github":
            collector = GitHubCollector(vcs_url=vcs_url, purl=purl)
        else:
            print(f"Unsupported VCS URL: {vcs_url}")
            continue

        status_code, error_msg = collector.execute()
        print(error_msg)

    sys.exit(0)
