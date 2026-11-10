"""Job agent: fetch -> filter -> score (Claude) -> fill form (Playwright) -> review/submit."""
import argparse, json, re, sqlite3, time
from pathlib import Path
import requests, yaml
from anthropic import Anthropic
from playwright.sync_api import sync_playwright

CFG = yaml.safe_load(open("config.yaml"))
P = CFG["profile"]
llm = Anthropic()  # reads ANTHROPIC_API_KEY
db = sqlite3.connect("jobs.db")
db.execute("""CREATE TABLE IF NOT EXISTS jobs(url TEXT PRIMARY KEY, company TEXT, title TEXT,
              score INT, status TEXT, note TEXT, ts DEFAULT CURRENT_TIMESTAMP)""")


def ask(prompt: str) -> dict:
    r = llm.messages.create(model=CFG["model"], max_tokens=2000,
                            messages=[{"role": "user", "content": prompt}])
    text = re.sub(r"```json|```", "", r.content[0].text).strip()
    return json.loads(text)


def strip_html(s): return re.sub(r"<[^>]+>", " ", s or "")


# ---------- 1. fetch ----------
def fetch_jobs():
    jobs = []
    for slug in CFG.get("greenhouse", []):
        try:
            d = requests.get(f"https://boards-api.greenhouse.io/v1/boards/{slug}/jobs?content=true", timeout=20).json()
            for j in d.get("jobs", []):
                jobs.append(dict(company=slug, title=j.get("title") or "", url=j["absolute_url"],
                                 location=(j.get("location") or {}).get("name") or "",
                                 description=strip_html(j.get("content", ""))[:6000]))
        except Exception as e:
            print(f"[warn] greenhouse/{slug}: {e}")
    for slug in CFG.get("lever", []):
        try:
            for j in requests.get(f"https://api.lever.co/v0/postings/{slug}?mode=json", timeout=20).json():
                jobs.append(dict(company=slug, title=j.get("text") or "", url=j["hostedUrl"],
                                 location=(j.get("categories") or {}).get("location") or "",
                                 description=(j.get("descriptionPlain") or "")[:6000]))
        except Exception as e:
            print(f"[warn] lever/{slug}: {e}")
    return jobs


# ---------- 2. filter (case-insensitive) ----------
def _matches(keywords, text, whole_word=False):
    """True if any keyword appears in text, ignoring upper/lower case.
    Keywords must start at a word boundary; with whole_word they must also end at one
    (so 'intern' does not match 'International')."""
    text = text.lower()
    for k in keywords or []:
        k = re.escape(str(k).strip().lower())
        if not k:
            continue
        pattern = rf"\b{k}\b" if whole_word else rf"\b{k}"
        if re.search(pattern, text):
            return True
    return False


def passes_filters(j):
    f = CFG["filters"]
    title = j.get("title") or ""
    loc = j.get("location") or ""
    return (_matches(f.get("title_include"), title)
            and not _matches(f.get("title_exclude"), title, whole_word=True)
            and _matches(f.get("location_include"), loc))


# ---------- 3. score ----------
def score(j):
    return ask(f"""Rate how well this job fits the candidate, 0-100. Be strict.
Candidate target: {P['target_roles']}
Candidate background:
{P['summary']}

Job: {j['title']} at {j['company']} ({j['location']})
{j['description']}

Reply with JSON only: {{"score": int, "reason": "one sentence"}}""")


# ---------- 4. fill ----------
FIELD_JS = """() => [...document.querySelectorAll('input,textarea,select')]
  .filter(e => e.type!=='hidden' && e.type!=='file' && e.type!=='submit' && e.offsetParent!==null)
  .map((e,i) => { e.setAttribute('data-ja', i);
    const lab = (e.labels && e.labels[0] && e.labels[0].innerText) || e.getAttribute('aria-label') || e.placeholder || e.name || '';
    return {id:i, tag:e.tagName.toLowerCase(), type:e.type, label:lab.trim().slice(0,300),
            required:e.required || e.getAttribute('aria-required')==='true',
            options: e.tagName==='SELECT' ? [...e.options].map(o=>o.text) : null}; })"""


def plan_answers(j, fields):
    return ask(f"""You are filling a job application for the candidate. Use ONLY the facts below.
If a field needs info not provided (or you're unsure), set its value to null. Never invent
employment, degrees, or numbers. For free-text questions write 2-4 honest, specific sentences
grounded in the facts and the job description.

Candidate profile: {json.dumps(P)}

Job: {j['title']} at {j['company']}
{j['description'][:3000]}

Form fields: {json.dumps(fields)}

Reply JSON only: {{"<field id>": <string | true | false | null>, ...}}
For selects use one of the listed options exactly. For checkboxes use true/false.""")


def fill_form(page, j):
    fields = page.evaluate(FIELD_JS)
    answers = plan_answers(j, fields)
    unknown_required = []
    for f in fields:
        v = answers.get(str(f["id"]))
        el = page.locator(f'[data-ja="{f["id"]}"]')
        if v is None:
            if f["required"]: unknown_required.append(f["label"])
            continue
        try:
            if f["tag"] == "select": el.select_option(label=str(v))
            elif f["type"] in ("checkbox", "radio"):
                if v: el.check()
            else: el.fill(str(v))
        except Exception as e:
            if f["required"]: unknown_required.append(f["label"])
            print(f"   [warn] couldn't fill '{f['label']}': {e}")
    resume = Path(P["resume_path"]).expanduser()
    if page.locator('input[type=file]').count() and resume.exists():
        page.locator('input[type=file]').first.set_input_files(str(resume))
    return unknown_required


def apply(j, sc, browser):
    page = browser.new_page()
    page.goto(j["url"], wait_until="domcontentloaded")
    # Lever hosts the form on /apply
    if "lever.co" in j["url"] and not j["url"].endswith("/apply"):
        page.goto(j["url"].rstrip("/") + "/apply", wait_until="domcontentloaded")
    page.wait_for_timeout(2500)
    missing = fill_form(page, j)
    Path("screenshots").mkdir(exist_ok=True)
    shot = f"screenshots/{j['company']}-{re.sub(r'[^a-z0-9]+','-',j['title'].lower())[:40]}.png"
    page.screenshot(path=shot, full_page=True)

    mode = CFG["mode"]
    if mode == "dry_run":
        status = "dry_run"
    elif mode == "review" or missing or sc < CFG["auto_min_score"]:
        print(f"   Needs your input: {missing or 'nothing, just review'}")
        ans = input("   Review the form in the browser. Submit it yourself, then type y (applied) / n (skip): ")
        status = "applied" if ans.strip().lower() == "y" else "skipped"
    else:
        page.locator('button[type=submit], input[type=submit]').first.click()
        page.wait_for_timeout(4000)
        status = "applied_auto"
    page.close()
    return status, ("missing: " + ", ".join(missing)) if missing else shot


# ---------- main ----------
def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--list", action="store_true", help="show tracker")
    if ap.parse_args().list:
        for r in db.execute("SELECT status,score,company,title,url FROM jobs ORDER BY ts DESC"): print(r)
        return

    seen = {r[0] for r in db.execute("SELECT url FROM jobs")}
    cands = [j for j in fetch_jobs() if j["url"] not in seen and passes_filters(j)]
    print(f"{len(cands)} new jobs passed filters (mode={CFG['mode']})")

    done = 0
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=(CFG["mode"] == "auto"))
        for j in cands:
            if done >= CFG["max_applications_per_run"]: break
            try:
                s = score(j)
            except Exception as e:
                print(f"[warn] scoring failed: {e}"); continue
            print(f"- {j['company']}: {j['title']}  score={s['score']}  ({s['reason']})")
            if s["score"] < CFG["min_score"]:
                db.execute("INSERT INTO jobs VALUES(?,?,?,?,?,?,CURRENT_TIMESTAMP)",
                           (j["url"], j["company"], j["title"], s["score"], "low_score", s["reason"]))
                db.commit(); continue
            try:
                status, note = apply(j, s["score"], browser)
            except Exception as e:
                status, note = "error", str(e)[:200]
            db.execute("INSERT INTO jobs VALUES(?,?,?,?,?,?,CURRENT_TIMESTAMP)",
                       (j["url"], j["company"], j["title"], s["score"], status, note))
            db.commit(); done += 1
            time.sleep(5)  # be polite
        browser.close()
    print("Done. Run `python job_agent.py --list` to see the tracker.")


if __name__ == "__main__":
    main()