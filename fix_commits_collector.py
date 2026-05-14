#
# Copyright (c) nexB Inc. and others. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import hashlib
import json
import re
import shutil
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from aboutcode.pipeline import BasePipeline, LoopProgress
from git import Repo
from packageurl.contrib.url2purl import url2purl


class CollectVCSFixCommitPipeline(BasePipeline):
    """
    Pipeline to collect fix commits from any git repository.
    """

    vcs_url: str
    patterns: list[str] = [
        r"\bCVE-\d{4}-\d{4,19}\b",
        r"GHSA-[2-9cfghjmpqrvwx]{4}-[2-9cfghjmpqrvwx]{4}-[2-9cfghjmpqrvwx]{4}",
    ]

    def __init__(self, vcs_url: str, *args, **kwargs):
        self.vcs_url = vcs_url
        super().__init__(*args, **kwargs)

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_fix_commits,
            cls.store_items,
            cls.clean_downloads,
        )

    def log(self, message):
        now_local = datetime.now(timezone.utc).astimezone()
        timestamp = now_local.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        message = f"{timestamp} {message}"
        print(message)

    def clone(self):
        """Clone the repository."""
        self.repo = Repo.clone_from(
            url=self.vcs_url,
            to_path=tempfile.mkdtemp(),
            bare=True,
            no_checkout=True,
            multi_options=["--filter=blob:none"],
        )

    def extract_vulnerability_id(self, commit) -> list[str]:
        """
        Extract vulnerability id from a commit message and returns a list of matched vulnerability IDs
        """
        matches = []
        for pattern in self.patterns:
            found = re.findall(pattern, commit.message, flags=re.IGNORECASE)
            matches.extend(found)
        return matches

    def collect_fix_commits(self):
        """
        Iterate through repository commits and group them by vulnerability identifiers.
        """
        self.log(
            "Processing git repository fix commits (grouped by vulnerability IDs)."
        )

        self.collected_items = {
            "vcs_url": self.vcs_url,
            "vulnerabilities": defaultdict(dict),
        }

        for commit in self.repo.iter_commits("--all"):
            matched_ids = self.extract_vulnerability_id(commit)
            if not matched_ids:
                continue

            commit_id = commit.hexsha
            commit_message = commit.message.strip()

            for vuln_id in matched_ids:
                vuln_id = vuln_id.upper()
                self.collected_items["vulnerabilities"][vuln_id][
                    commit_id
                ] = commit_message

        self.log(
            f"Found {len(self.collected_items)} vulnerabilities with related commits."
        )
        self.log("Finished processing all commits.")
        return self.collected_items

    def store_items(self):
        """Storing collected fix commits for this repository"""
        self.log("Storing collected fix commits")
        purl = url2purl(self.vcs_url)

        if not (purl and purl.name) or not self.collected_items.get("vulnerabilities"):
            self.log("Nothing to store for collected fix commits")
            return

        vcs_url_hash = hashlib.sha256(self.vcs_url.encode("utf-8")).hexdigest()[:8]
        path = Path(f"data/fix-commits/{purl.name}-{vcs_url_hash}.json")
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.collected_items, f, indent=2)
        return

    def clean_downloads(self):
        """Cleanup any temporary repository data"""
        self.log("Cleaning up local repository resources")
        if hasattr(self, "repo") and self.repo.working_dir:
            shutil.rmtree(path=self.repo.working_dir)


if __name__ == "__main__":
    with open("config/fix_commits_targets.json") as f:
        vcs_urls = json.load(f)

    progress = LoopProgress(
        total_iterations=len(vcs_urls),
        logger=print,
    )

    for vcs_url in progress.iter(vcs_urls):
        status_code, error_msg = CollectVCSFixCommitPipeline(vcs_url=vcs_url).execute()
        print(error_msg)

    sys.exit(0)
