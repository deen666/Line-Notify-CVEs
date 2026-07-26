# Line-Notify-CVEs

An early personal project: a small Google Apps Script that polls a public CVE feed
and pushes new high-severity entries into a LINE chat room. LINE is the dominant
workplace chat platform in Thailand, so delivering alerts there keeps CVE
awareness inside the tool a team already uses all day.

## What it does
- Fetches the most recent CVEs from the CIRCL CVE API (`https://cve.circl.lu/api/last`).
- Iterates the 30 most recent entries and keeps only those with CVSS >= 6.
- Formats each one with CVE ID, summary, CVSS score, references, last-modified date
  and assigner, converted to GMT+7.
- Posts each alert to LINE Notify (`https://notify-api.line.me/api/notify`).

For example

![](https://raw.githubusercontent.com/deen666/Line-Notify-CVEs/main/Line-Noti-Update.jpg)

## Setup
1. Copy `cve.gs` into a new Google Apps Script project.
2. Set your LINE Notify token in the `token` variable (the value in the repo is a
   placeholder).
3. Adjust the CVSS threshold and timezone if needed.
4. Add a time-based trigger for the `CVE()` function — the script itself does not
   schedule anything.

## Status
Archived / historical. Written early in my security career. Both upstream
dependencies have changed since: LINE Notify has been retired by LINE, and the
CIRCL API endpoint may have moved. Kept public as a reference for
notification-driven CVE monitoring rather than as a maintained tool.


by [DEEN](https://github.com/deen666)
