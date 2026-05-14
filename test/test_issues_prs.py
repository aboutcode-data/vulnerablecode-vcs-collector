#
# Copyright (c) nexB Inc. and others. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from unittest.mock import MagicMock, patch

import pytest
from packageurl import PackageURL

from issues_prs_collector import GitHubCollector, GitLabCollector


class TestGitHubCollector:
    def setup_method(self):
        purl = PackageURL(type="github", namespace="aboutcode-org", name="test")
        self.github_collector = GitHubCollector(
            vcs_url="https://github.com/aboutcode-org/test", purl=purl
        )

    @patch("os.getenv", return_value=None)
    def test_missing_token(self, mock_getenv):
        with pytest.raises(
            ValueError, match="GH_API_TOKEN environment variable not set properly"
        ):
            self.github_collector.fetch_entries()

    def test_collect_items(self):
        issue1 = MagicMock()
        issue1.title = "Fix CVE-2024-1234"
        issue1.body = "test description"
        issue1.html_url = "https://github.com/aboutcode-org/test/issues/1"

        pr1 = MagicMock()
        pr1.title = "Bump deps"
        pr1.body = "Fixes CVE-2024-5678"
        pr1.html_url = "https://github.com/aboutcode-org/test/pulls/1"

        self.github_collector.issues = [issue1]
        self.github_collector.prs = [pr1]

        self.github_collector.collect_items()

        assert self.github_collector.collected_items["vulnerabilities"] == {
            "CVE-2024-1234": {
                "Issues": ["https://github.com/aboutcode-org/test/issues/1"],
                "PRs": [],
            },
            "CVE-2024-5678": {
                "Issues": [],
                "PRs": ["https://github.com/aboutcode-org/test/pulls/1"],
            },
        }


class TestGitLabCollector:
    def setup_method(self):
        purl = PackageURL(type="gitlab", namespace="gitlab-org", name="gitlab-foss")
        self.gitlab_collector = GitLabCollector(
            vcs_url="https://gitlab.com/gitlab-org/gitlab-foss", purl=purl
        )

    @patch("os.getenv", return_value=None)
    def test_missing_token(self, mock_getenv):
        with pytest.raises(
            ValueError, match="GLAB_API_TOKEN environment variable not set properly"
        ):
            self.gitlab_collector.fetch_entries()

    def test_collect_items(self):
        self.gitlab_collector.issues = [
            {
                "title": "Need security update for CVE-2018-11235",
                "description": "At the end of May, a severe security vulnerability was discovered in Git that pertains to submodules..",
                "web_url": "https://gitlab.com/gitlab-org/gitlab-foss/-/issues/29992",
            },
            {
                "title": "Bump KaTeX version",
                "description": "No cve here",
                "web_url": "https://gitlab.com/gitlab-org/gitlab-foss/-/issues/51065",
            },
        ]
        self.gitlab_collector.prs = [
            {
                "title": "Temporarily ignore Nokogiri CVE-2016-4658",
                "description": "we can't do anything about it quickly, so we'll ignore the CVE in bundle-audit.",
                "web_url": "https://gitlab.com/gitlab-org/gitlab-foss/-/merge_requests/10218",
            }
        ]

        self.gitlab_collector.collect_items()
        assert self.gitlab_collector.collected_items["vulnerabilities"] == {
            "CVE-2018-11235": {
                "Issues": ["https://gitlab.com/gitlab-org/gitlab-foss/-/issues/29992"],
                "PRs": [],
            },
            "CVE-2016-4658": {
                "Issues": [],
                "PRs": [
                    "https://gitlab.com/gitlab-org/gitlab-foss/-/merge_requests/10218"
                ],
            },
        }
