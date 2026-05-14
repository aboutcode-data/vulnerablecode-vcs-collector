# vulnerablecode-vcs-collector
Collect data ( fix commits , issues, prs ) related to vulnerabilities 


#### Fix commits:
To collect fix commits we clone the target git repo and loop over every git commit message searching for ( CVE-id or GHSA-id ) 

File structure:

```json
{
  "vcs_url": "https://github.com/mirror/busybox",
  "vulnerabilities": {
    "CVE-2023-42363": {
      "fb08d43d44d1fea1f741fafb9aa7e1958a5f69aa": "awk: fix use after free (CVE-2023-42363)\n\nfunction                                             old     new   delta\nevaluate                                            3377    3385      +8\n\nFixes https://bugs.busybox.net/show_bug.cgi?id=15865\n\nSigned-off-by: Natanael Copa <ncopa@alpinelinux.org>\nSigned-off-by: Denys Vlasenko <vda.linux@googlemail.com>"
    }
  }
}
```

#### Issues and PRs:
To collect issues and pull requests we are using Github/Gitlab API to do quick search by `CVE-`

File structure:

```json
{
  "vcs_url": "https://github.com/python/cpython",
  "vulnerabilities": {
    "CVE-2026-2297": {
      "Issues": [
        "https://github.com/python/cpython/issues/145506"
      ],
      "PRs": [
        "https://github.com/python/cpython/pull/145514",
        "https://github.com/python/cpython/pull/145516",
        "https://github.com/python/cpython/pull/145515",
        "https://github.com/python/cpython/pull/145507",
        "https://github.com/python/cpython/pull/145512",
        "https://github.com/python/cpython/pull/145513"
      ]
    }
  }
}
```

### File Naming
The results are stored in a json file `{repo_name}-{repo_url_hash}.json` ex: `nginx-9251c307.json`

**Notes:** `repo_url_hash` represents the first 8 characters of repository url `SHA-256` hash
## Usage

To get started, clone the repository:

```bash
git clone https://github.com/aboutcode-data/vulnerablecode-vcs-collector.git
```


Once cloned, you can find the existing data in the `data/fix-commits` or `data/issues-prs` directory

To run the pipeline and generate new files, Create the `.env` file and add your API tokens:

```json
GH_API_TOKEN="ghp_xxx"
GLAB_API_TOKEN="glpat-xxx"
```

Then, you can run the collectors using Python:

To collect fix commits:
```bash
python fix_commits_collector.py
```

To collect issues and pull requests:
```bash
python issues_prs_collector.py
```

## Testing

Ensure you have `pytest` installed by running this command:
```bash
pip install pytest
```

Then, you can run the tests using this command:
```bash
python -m pytest test/ -v
```

