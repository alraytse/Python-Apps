import io, re, json
from datetime import datetime
from pathlib import Path

import streamlit as st
from pypdf import PdfReader
from docx import Document
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

APP_DIR = Path(__file__).parent
DATA_DIR = APP_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
QUEUE_FILE = DATA_DIR / "applications.json"

st.set_page_config(page_title="AI Network Job Agent", page_icon="🌐", layout="wide")

SKILL_GROUPS = {
    "Routing & switching": ["bgp", "ospf", "isis", "mpls", "tcp/ip", "routing", "switching", "ecmp"],
    "Data center fabrics": ["vxlan", "evpn", "leaf-spine", "clos", "nexus", "aci", "apic", "fabric"],
    "Cloud & security": ["aws", "azure", "gcp", "cloud", "palo alto", "firewall", "segmentation", "vrf"],
    "AI / HPC networking": ["rdma", "roce", "infiniband", "hpc", "nccl", "400g", "800g", "gpu", "ai infrastructure"],
    "Automation & operations": ["python", "ansible", "terraform", "automation", "wireshark", "servicenow", "monitoring", "incident"],
    "Wireless & SD-WAN": ["sd-wan", "viptela", "meraki", "wireless", "lan", "wan"],
}

ROLE_TERMS = [
    "network engineer", "network architect", "data center network", "ai network",
    "hpc network", "network automation", "infrastructure engineer", "cloud network"
]

def extract_resume(upload):
    if upload is None:
        return ""
    raw = upload.getvalue()
    name = upload.name.lower()
    if name.endswith(".pdf"):
        reader = PdfReader(io.BytesIO(raw))
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    if name.endswith(".docx"):
        doc = Document(io.BytesIO(raw))
        return "\n".join(p.text for p in doc.paragraphs)
    return raw.decode("utf-8", errors="ignore")

def clean(text):
    return re.sub(r"\s+", " ", (text or "")).strip()

def skills_found(text):
    low = text.lower()
    return {group: [s for s in skills if s in low] for group, skills in SKILL_GROUPS.items() if any(s in low for s in skills)}

def match_job(resume, job):
    # Explainable hybrid score: semantic TF-IDF similarity + skill overlap.
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words="english")
    try:
        matrix = vectorizer.fit_transform([resume, job])
        semantic = float(cosine_similarity(matrix[0:1], matrix[1:2])[0][0])
    except ValueError:
        semantic = 0.0

    resume_skills = set(s for vals in skills_found(resume).values() for s in vals)
    job_skills = set(s for vals in skills_found(job).values() for s in vals)
    overlap = len(resume_skills & job_skills) / max(1, len(job_skills))
    score = round(100 * (0.45 * semantic + 0.55 * overlap))
    missing = sorted(job_skills - resume_skills)
    matched = sorted(job_skills & resume_skills)
    return score, semantic, matched, missing

def make_cover_letter(candidate, company, role, resume, job):
    resume_skills = skills_found(resume)
    skill_text = []
    for group, vals in resume_skills.items():
        if vals:
            skill_text.append(f"{group}: {', '.join(vals[:6])}")
    evidence = "; ".join(skill_text[:4]) or "enterprise networking and infrastructure engineering"
    return f"""Dear Hiring Manager,

I am interested in the {role} opportunity at {company}. I bring extensive experience in enterprise networking, data center infrastructure, and production network engineering, with a focus on reliable architecture, implementation, and troubleshooting.

My background includes {evidence}. I have worked across complex network environments, partnering with infrastructure, security, and application teams to deliver resilient solutions and manage change safely. I am particularly interested in applying this experience to the challenges described in your role, while continuing to grow in AI infrastructure and high-performance networking.

I would welcome the opportunity to discuss how my technical background, customer focus, and operational discipline could contribute to {company}.

Sincerely,
{candidate}
"""

def load_queue():
    if QUEUE_FILE.exists():
        try:
            return json.loads(QUEUE_FILE.read_text())
        except Exception:
            return []
    return []

def save_queue(items):
    QUEUE_FILE.write_text(json.dumps(items, indent=2))

st.title("🌐 AI/ML Network Job Agent")
st.caption("A local-first MVP for resume matching, application drafting, and human-approved application tracking.")

with st.sidebar:
    st.header("Candidate profile")
    candidate = st.text_input("Your name", "Alex Raytselsky")
    email = st.text_input("Email", "alraytse@yahoo.com")
    phone = st.text_input("Phone", "(408) 636-3224")
    linkedin = st.text_input("LinkedIn", "linkedin.com/in/alex-raytselsky-840147")
    st.divider()
    st.caption("Privacy: resume text and saved application records stay in this app's local project folder. Do not upload sensitive information you do not want processed.")

tab1, tab2, tab3 = st.tabs(["1 · Resume & matching", "2 · Draft application", "3 · Approval tracker"])

with tab1:
    st.subheader("Upload your resume")
    resume_file = st.file_uploader("PDF, DOCX, or TXT", type=["pdf", "docx", "txt"], key="resume")
    resume_text = extract_resume(resume_file) if resume_file else ""
    if resume_text:
        st.success(f"Resume loaded · {len(resume_text.split())} words")
        with st.expander("Preview extracted resume text"):
            st.text_area("Resume text", resume_text, height=220)
    else:
        st.info("Upload a resume to enable matching. You can also paste resume text below.")
        resume_text = st.text_area("Or paste resume text", height=220, key="resume_paste")

    st.subheader("Paste a job description")
    job_title = st.text_input("Job title", "Senior Network Engineer")
    company = st.text_input("Company", "")
    job_url = st.text_input("Job posting URL (optional)", "")
    job_text = st.text_area("Job description", height=250, placeholder="Paste the full job description here...")
    if st.button("Analyze match", type="primary", disabled=not (resume_text.strip() and job_text.strip())):
        score, semantic, matched, missing = match_job(resume_text, job_text)
        st.session_state["analysis"] = {
            "score": score, "semantic": semantic, "matched": matched,
            "missing": missing, "resume": resume_text, "job": job_text,
            "title": job_title, "company": company, "url": job_url
        }

    if "analysis" in st.session_state:
        a = st.session_state["analysis"]
        st.divider()
        c1, c2, c3 = st.columns(3)
        c1.metric("Overall match", f'{a["score"]}%')
        c2.metric("Text similarity", f'{a["semantic"]:.0%}')
        c3.metric("Matched job skills", len(a["matched"]))
        st.progress(a["score"] / 100)
        left, right = st.columns(2)
        with left:
            st.markdown("**Skills found in both**")
            st.write(", ".join(a["matched"]) if a["matched"] else "No direct skill overlap detected.")
        with right:
            st.markdown("**Job skills not detected in resume**")
            st.write(", ".join(a["missing"]) if a["missing"] else "No missing skills detected from the built-in skill dictionary.")
        st.caption("This is a heuristic screening aid, not a hiring prediction. Review the job description and verify every skill claim.")

with tab2:
    st.subheader("Prepare a tailored application")
    a = st.session_state.get("analysis")
    if not a:
        st.info("Analyze a job in the first tab to generate a draft.")
    else:
        letter = make_cover_letter(candidate, a["company"] or "the company", a["title"], a["resume"], a["job"])
        st.text_area("Editable cover letter", letter, height=300, key="letter")
        st.markdown("**Application profile details**")
        st.code(f"Name: {candidate}\nEmail: {email}\nPhone: {phone}\nLinkedIn: {linkedin}")
        st.warning("Review and edit all content before use. The agent does not submit applications or invent qualifications.")
        if st.button("Add to approval tracker", type="primary"):
            items = load_queue()
            items.append({
                "created_at": datetime.now().isoformat(timespec="minutes"),
                "candidate": candidate, "email": email, "phone": phone,
                "linkedin": linkedin, "company": a["company"], "title": a["title"],
                "url": a["url"], "score": a["score"],
                "cover_letter": st.session_state.get("letter", letter),
                "status": "Needs review / approval"
            })
            save_queue(items)
            st.success("Draft added to your local approval tracker.")

with tab3:
    st.subheader("Application approval tracker")
    items = load_queue()
    if not items:
        st.info("No drafts saved yet. Analyze a job and add it from the Draft application tab.")
    else:
        for i, item in enumerate(items):
            with st.expander(f'{item.get("company") or "Company not entered"} · {item.get("title")} · {item.get("score", 0)}% match'):
                st.write(f'Created: {item.get("created_at")}')
                st.write(f'Status: {item.get("status")}')
                if item.get("url"):
                    st.markdown(f'[Open job posting]({item["url"]})')
                st.text_area("Saved cover letter", item.get("cover_letter", ""), height=180, key=f"saved_{i}")
                cols = st.columns(2)
                if cols[0].button("Mark approved", key=f"approve_{i}"):
                    items[i]["status"] = "Approved by user — ready for manual submission"
                    save_queue(items)
                    st.rerun()
                if cols[1].button("Mark submitted", key=f"submitted_{i}"):
                    items[i]["status"] = "Submitted by user"
                    save_queue(items)
                    st.rerun()
        st.download_button("Download application tracker (JSON)", json.dumps(items, indent=2), "applications.json", "application/json")
