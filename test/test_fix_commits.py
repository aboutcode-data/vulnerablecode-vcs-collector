#
# Copyright (c) nexB Inc. and others. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from unittest.mock import MagicMock

import pytest

from fix_commits_collector import CollectVCSFixCommitPipeline


class TestCollectVCSFixCommitPipeline:
    def test_collect_fix_commits(self):
        vcs_url = "https://github.com/aboutcode-org/test"
        pipeline = CollectVCSFixCommitPipeline(vcs_url=vcs_url)

        pipeline.repo = MagicMock()
        commit_1 = MagicMock(
            hexsha="dd7769fbc97c84545579cebf1dc4838214098a11",
            message=" fixes cve-2023-40024 \n",
        )
        commit_2 = MagicMock(
            hexsha="ab801c46c0b0e8b921f690ea47c927379e8862a3",
            message="Update README file",
        )
        commit_3 = MagicMock(
            hexsha="ab801c46c0b0e8b921f690ea47c927379e8862a3",
            message="Patch CVE-2026-21711 and GHSA-vcqx-cqfc-xc2r",
        )

        pipeline.repo.iter_commits.return_value = [commit_1, commit_2, commit_3]
        result = pipeline.collect_fix_commits()

        assert result["vcs_url"] == vcs_url
        assert result["vulnerabilities"] == {
            "CVE-2023-40024": {
                "dd7769fbc97c84545579cebf1dc4838214098a11": "fixes cve-2023-40024"
            },
            "CVE-2026-21711": {
                "ab801c46c0b0e8b921f690ea47c927379e8862a3": "Patch CVE-2026-21711 and GHSA-vcqx-cqfc-xc2r"
            },
            "GHSA-VCQX-CQFC-XC2R": {
                "ab801c46c0b0e8b921f690ea47c927379e8862a3": "Patch CVE-2026-21711 and GHSA-vcqx-cqfc-xc2r"
            },
        }


@pytest.mark.parametrize(
    "commit_message, expected_matches",
    [
        ("Update README.md with instructions", []),
        ("Fixes CVE-2023-12345 in the backend", ["CVE-2023-12345"]),
        ("Fix GHSA-2ggp-cmvm-f62f here", ["GHSA-2ggp-cmvm-f62f"]),
        (
            "fixes cve-2026-21711 and ghsa-vcqx-cqfc-xc2r",
            ["cve-2026-21711", "ghsa-vcqx-cqfc-xc2r"],
        ),
        ("Fix CVE-2020-123456789gff0", []),
    ],
)
def test_extract_vulnerability_id(commit_message, expected_matches):
    pipeline = CollectVCSFixCommitPipeline(
        vcs_url="https://github.com/aboutcode-org/test"
    )
    commit = MagicMock()
    commit.message = commit_message
    result = pipeline.extract_vulnerability_id(commit)
    assert set(result) == set(expected_matches)
