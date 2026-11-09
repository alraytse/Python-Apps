#!/usr/bin/env python3
"""
Job search agent: searches the web for postings, scores them against your
profile, skips ones you've already seen, and saves matches to a CSV.

Setup:
    pip install anthropic
    python job_agent.py   # you'll be prompted for your API key (input is hidden)
"""

import csv
import getpass
import json
import os
import re
from datetime import date

import anthropic

MODEL = "claude-sonnet-5-5"
PROFILE_PATH = "profile.json"
SEEN_PATH = "seen_jobs.json"
OUTPUT_PATH = "jobs.csv"
CSV_FIELDS = ["date_found", "score", "title", "company", "location",
              "salary", "url", "why_it_fits", "concerns"]

SYSTEM = """You are a job search agent. You search the web for current job \
postings and evaluate each one honestly against the candidate's profile.

Rules:
- Only return postings you actually found via search, with a real URL to the \
posting or the company's careers page. Never invent jobs or URLs.
- Prefer company career pages and major job boards over aggregators/spam.
- Skip anything that looks expired, duplicated, or hits a dealbreaker.
- If salary isn't listed, write "not listed". Never guess it.
- Score 1-10 on fit (10 = near-perfect match). Be strict; most jobs are 4-6.
- Your final message must be ONLY a JSON array, no prose, no code fences."""


def load_json(path, default):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return default


def prompt_for_api_key():
    # getpass hides the input as you type/paste it.
    key = getpass.getpass("Enter your Anthropic API key: ").strip()
    if not key:
        raise SystemExit("No API key entered.")
    return key


def build_prompt(profile):
    return f"""Find job postings that match this candidate profile:

{json.dumps(profile, indent=2)}

Run several different searches (vary titles, boards, and phrasing). Posted \
within the last {profile.get('posted_within_days', 14)} days. Today is {date.today()}.

Return up to {profile.get('max_results', 15)} results as a JSON array where each \
item has exactly these keys:
"title", "company", "location", "salary", "url", "score" (integer 1-10), \
"why_it_fits" (one sentence), "concerns" (one sentence, or "none")."""


def run_search(client, profile):
    messages = [{"role": "user", "content": build_prompt(profile)}]
    tools = [{"type": "web_search_20250305", "name": "web_search", "max_uses": 15}]

    # Long searches can pause mid-turn; keep going until Claude finishes.
    for _ in range(6):
        resp = client.messages.create(
            model=MODEL,
            max_tokens=4000,
            system=SYSTEM,
            tools=tools,
            messages=messages,
        )
        if resp.stop_reason != "pause_turn":
            break
        messages.append({"role": "assistant", "content": resp.content})

    return "".join(b.text for b in resp.content if b.type == "text")


def parse_jobs(text):
    start, end = text.find("["), text.rfind("]")
    if start == -1 or end == -1:
        raise ValueError(f"No JSON array found in response:\n{text[:500]}")
    return json.loads(text[start:end + 1])


def normalize_url(url):
    # Strip tracking params so the same job isn't saved twice.
    return re.sub(r"[?#].*$", "", url.strip().lower()).rstrip("/")


def main():
    profile = load_json(PROFILE_PATH, None)
    if profile is None:
        raise SystemExit(f"Missing {PROFILE_PATH}")

    client = anthropic.Anthropic(api_key=prompt_for_api_key())
    print("Searching... (this can take a minute or two)")
    jobs = parse_jobs(run_search(client, profile))

    seen = set(load_json(SEEN_PATH, []))
    min_score = profile.get("min_score", 7)
    new_jobs = []
    for job in jobs:
        key = normalize_url(job.get("url", ""))
        if not key or key in seen:
            continue
        seen.add(key)  # remember everything, even low scorers
        if int(job.get("score", 0)) >= min_score:
            new_jobs.append(job)

    new_jobs.sort(key=lambda j: int(j["score"]), reverse=True)

    write_header = not os.path.exists(OUTPUT_PATH)
    with open(OUTPUT_PATH, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        if write_header:
            writer.writeheader()
        for j in new_jobs:
            writer.writerow({
                "date_found": date.today().isoformat(),
                "score": j["score"],
                "title": j.get("title", ""),
                "company": j.get("company", ""),
                "location": j.get("location", ""),
                "salary": j.get("salary", "not listed"),
                "url": j.get("url", ""),
                "why_it_fits": j.get("why_it_fits", ""),
                "concerns": j.get("concerns", ""),
            })

    with open(SEEN_PATH, "w") as f:
        json.dump(sorted(seen), f, indent=2)

    print(f"\nFound {len(jobs)} postings, {len(new_jobs)} new matches (score >= {min_score}):\n")
    for j in new_jobs:
        print(f"[{j['score']}/10] {j['title']} @ {j['company']} ({j.get('location', '?')})")
        print(f"        {j.get('salary', 'not listed')} | {j['url']}")
        print(f"        + {j.get('why_it_fits', '')}")
        print(f"        - {j.get('concerns', 'none')}\n")
    print(f"Saved to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
