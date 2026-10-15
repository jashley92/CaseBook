#!/usr/bin/env bash
# BUG-466: a release must not ship a commit whose SonarQube Cloud quality gate failed. The release workflow's own CI run
# skips Sonar (analysis is for main and PRs, not tags), so this asks SonarQube Cloud for the analysis that CI on main
# made of the tagged commit and refuses unless its quality gate passed.
#
# Finds the newest analysis of <sha> on the branch (newest first, paged, from the commit's date on), then reads that
# analysis's quality gate. Main's CI may still be running when the tag is pushed, so a missing analysis is retried for
# SONAR_WAIT_SECONDS. A release-notes commit that only touches paths ci.yml ignores (*.md, docs/, LICENSE, .gitignore)
# gets no CI run of its own when pushed alone, and its changes can't move the gate, so an analysis of any commit from
# the newest one before it that touches anything else up to the tag also counts (a push is analysed under its last
# commit, which may itself be a docs commit). A commit with neither (CI on main failed before Sonar, or
# the commit isn't on main) fails once the wait runs out: tag a commit whose CI on main passed.
#
# Usage: tools/ci/check-sonar-quality-gate.sh [<sha>]      (default: $GITHUB_SHA, else HEAD)
# Env:   SONAR_TOKEN (absent: skipped with a warning, as on forks), SONAR_HOST_URL (https://sonarcloud.io),
#        SONAR_PROJECT_KEY (jashley92_CaseBook), SONAR_BRANCH (main), SONAR_WAIT_SECONDS (900), SONAR_POLL_SECONDS (30)
# Needs: curl, jq, git (for the commit date; without it every page is searched).
set -euo pipefail
shopt -s inherit_errexit   # a failing jq or api call inside $(...) stops the check too

sha="${1:-${GITHUB_SHA:-$(git rev-parse HEAD)}}"
sha="$(git rev-parse --verify --quiet "$sha^{commit}" 2>/dev/null || echo "$sha")"   # a tag or short SHA, run locally
host="${SONAR_HOST_URL:-https://sonarcloud.io}"
host="${host%/}"
project="${SONAR_PROJECT_KEY:-jashley92_CaseBook}"
branch="${SONAR_BRANCH:-main}"
wait_seconds="${SONAR_WAIT_SECONDS:-900}"
poll_seconds="${SONAR_POLL_SECONDS:-30}"
page_size=100

if [[ -z "${SONAR_TOKEN:-}" ]]; then
  echo "::warning::SONAR_TOKEN is not set, so the SonarQube Cloud quality gate of $sha was NOT checked (expected on forks only)."
  exit 0
fi
if ! [[ "$sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "::error::'$sha' is not a commit (expected a SHA, a tag or another ref)."
  exit 1
fi

# GET <path?query> against the web API. curl retries transient failures itself; any other HTTP error (a bad token,
# an unknown project) stops the release with the body SonarQube Cloud returned.
api() {
  local out code
  out="$(mktemp)"
  code="$(curl -sS --retry 3 --retry-delay 5 --retry-all-errors --max-time 60 -o "$out" -w '%{http_code}' \
            -H "Authorization: Bearer $SONAR_TOKEN" "$host$1")" || code="000"
  if [[ "$code" != 200 ]]; then
    echo "::error::SonarQube Cloud API call $1 failed (HTTP $code): $(head -c 500 "$out" 2>/dev/null || true)" >&2
    rm -f "$out"
    return 1
  fi
  cat "$out"
  rm -f "$out"
}

# An analysis can't predate the commit, so start the search a day before the committer date (time zones, clock skew).
from=""
if commit_epoch="$(git show -s --format=%ct "$sha" 2>/dev/null)"; then
  from="$(date -u -d "@$((commit_epoch - 86400))" +%Y-%m-%d 2>/dev/null || true)"
fi

# BUG-466 follow-up: the newest commit at or before $sha that CI on main doesn't skip (keep in step with ci.yml's
# paths-ignore). v1.6.1 and v1.6.4 were tagged on release-notes commits.
code_sha="$(git log -1 --format=%H "$sha" -- . ':(exclude,glob)**/*.md' ':(exclude)docs' ':(exclude)LICENSE'               ':(exclude).gitignore' 2>/dev/null || true)"
code_sha="${code_sha:-$sha}"
if [[ "$code_sha" != "$sha" ]]; then
  echo "$sha changes only paths CI ignores since $code_sha; an analysis of any commit from there to the tag counts."
  if commit_epoch="$(git show -s --format=%ct "$code_sha" 2>/dev/null)"; then
    from="$(date -u -d "@$((commit_epoch - 86400))" +%Y-%m-%d 2>/dev/null || true)"
  fi
fi

# BUG-497: every commit from $code_sha to $sha has the same code, so an analysis of any of them stands for the tag.
revisions="$(echo "$code_sha"; git rev-list "$code_sha..$sha" 2>/dev/null || true)"
revisions_json="$(jq -Rn --arg extra "$sha" '[inputs, $extra] | unique' <<<"$revisions")"

# Prints the key of the newest analysis whose revision is one of $revisions, or nothing.
find_analysis() {
  local page=1 json key total
  while :; do
    json="$(api "/api/project_analyses/search?project=$project&branch=$branch&ps=$page_size&p=$page${from:+&from=$from}")" || return 1
    key="$(jq -r --argjson revs "$revisions_json"              '[.analyses[]? | select(.revision | IN($revs[]))][0].key // empty' <<<"$json")"
    if [[ -n "$key" ]]; then echo "$key"; return 0; fi
    total="$(jq -r '.paging.total // 0' <<<"$json")"
    (( page * page_size < total )) || return 0
    page=$((page + 1))
  done
}

deadline=$(( $(date +%s) + wait_seconds ))
while :; do
  analysis="$(find_analysis)"
  [[ -n "$analysis" ]] && break
  if (( $(date +%s) >= deadline )); then
    cat >&2 <<EOF
::error::No SonarQube Cloud analysis of $sha (or of any commit back to $code_sha, its newest one CI doesn't skip) on branch '$branch'
(project $project) after ${wait_seconds}s, so its quality gate is unknown and the release is refused. Either CI on
'$branch' failed before the Sonar step, the commit isn't on '$branch', or the analysis is still queued. Tag a commit
whose CI on '$branch' passed, or re-run this job.
EOF
    exit 1
  fi
  echo "No analysis of $sha on '$branch' yet (CI may still be running); checking again in ${poll_seconds}s..."
  sleep "$poll_seconds"
done

status_json="$(api "/api/qualitygates/project_status?analysisId=$analysis")"
status="$(jq -r '.projectStatus.status // "NONE"' <<<"$status_json")"
if [[ "$status" == OK ]]; then
  echo "SonarQube Cloud quality gate passed for $sha (analysis $analysis)."
  exit 0
fi

echo "::error::SonarQube Cloud quality gate is $status for $sha (analysis $analysis); the release is refused."
jq -r '.projectStatus.conditions[]? | select(.status != "OK")
       | "    \(.metricKey): \(.actualValue // "-") (\(.comparator // "") \(.errorThreshold // "-"))"' <<<"$status_json" || true
echo "Fix the failing conditions on '$branch' (or review them in SonarQube Cloud), then tag the commit that passes."
exit 1
