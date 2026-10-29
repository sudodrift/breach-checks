# Gitee keys and two scanners (October 2026)

Article: [26,400 working keys were sitting in public Gitee repos. One scanner would have caught about half.](https://sudodrift.github.io/posts/gitee-keys-two-scanners/)

## What happened

On October 28, 2026, researcher Ben Zimmermann published a scan of 7.25 million public Gitee repos ([MongoDB blog](https://www.mongodb.com/company/blog/technical/scanning-7-point-25-million-public-repositories-chinas-largest-git-platform-for-secrets)). TruffleHog and Kingfisher together found 26,400 unique working credentials, but only 1,001 were found by both tools. Each one missed a lot of what the other caught.

## What the script checks

- runs `trufflehog` and `kingfisher` over the full git history of one local repo
- merges the results by secret value and says which tool found each one
- says when a key sits in a file that is already deleted from the working tree
- prints the kind, the first few characters, the length and a short hash. It never prints a value.

This one is Python (standard library only) because it calls two outside tools and merges their JSON. Both tools must be on your `PATH`.

## How to run it

```sh
python3 two-scanner-check.py ~/code/my-repo              # each tool checks keys with their provider
python3 two-scanner-check.py ~/code/my-repo --no-verify  # pattern match only, no network
```

With validation on, the two tools (not this script) send found keys to the provider that issued them. Use `--no-verify` if you don't want that, and treat every hit as live. Only run it on your own repos.

## What a clean result does not prove

- It sees one local repo. Forks, other clones and anything a code host cached are out of reach.
- It only knows what the two tools' detectors know. A token with no fixed shape can slip past both.

## If it flags something

Revoke the key at the service that issued it first, then read that key's usage logs, then clean the history with `git filter-repo`. Deleting the file or rewriting history does not stop a key from working. The article has the steps for Alibaba Cloud, Google, OpenAI, DeepSeek, Zhipu and GitHub.
