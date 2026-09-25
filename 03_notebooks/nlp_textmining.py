import os, json, re
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import LatentDirichletAllocation, TruncatedSVD

OUT = "/home/claude/gridwatch/outputs"
CORPUS_DIR = "/home/claude/gridwatch/threat_intel"

MITRE_ICS_TACTICS = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Evasion", "Defense Evasion", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Inhibit Response Function",
    "Impair Process Control", "Impact",
]

docs, doc_ids = [], []
for fname in sorted(os.listdir(CORPUS_DIR)):
    if fname.endswith(".txt"):
        with open(f"{CORPUS_DIR}/{fname}") as f:
            docs.append(f.read())
            doc_ids.append(fname.replace(".txt", ""))

# --- Preprocessing ---
def clean(text):
    text = text.lower()
    text = re.sub(r"[^a-z\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

cleaned = [clean(d) for d in docs]

# --- Rule-based TTP/indicator extraction (keyword match against ATT&CK for ICS tactics) ---
extraction = {}
for doc_id, raw in zip(doc_ids, docs):
    found_tactics = [t for t in MITRE_ICS_TACTICS if t.lower() in raw.lower()]
    indicators_section = re.findall(r"Indicators observed:\n((?:- .+\n?)+)", raw)
    indicators = []
    if indicators_section:
        indicators = [line.strip("- ").strip() for line in indicators_section[0].strip().split("\n")]
    extraction[doc_id] = {"tactics_mentioned": found_tactics, "indicators": indicators}

# --- TF-IDF + simple topic modelling (LDA) over the small corpus ---
vectorizer = TfidfVectorizer(max_features=200, stop_words="english")
X = vectorizer.fit_transform(cleaned)
n_topics = min(2, len(docs))
lda = LatentDirichletAllocation(n_components=n_topics, random_state=42)
lda.fit(X)
terms = vectorizer.get_feature_names_out()
topics = []
for i, comp in enumerate(lda.components_):
    top_terms = [terms[idx] for idx in comp.argsort()[-8:][::-1]]
    topics.append({"topic": i, "top_terms": top_terms})

# --- Link extracted indicators to observed case evidence (from Section 7 output) ---
with open(f"{OUT}/metrics/incident_timeline_summary.json") as f:
    incident = json.load(f)

case_evidence_flags = incident["hypothesis_test"]["hypothesis_B_compromise"]["supported_by"]
case_to_intel_links = []
mapping = {
    "credential_access_edr_alert": "credential-dumping utility execution",
    "defense_evasion_edr_alert": "local logging service disabled shortly after logon",
    "ot_unauthorized_write": "unauthorized setpoint write attempt",
    "lateral_movement_multi_host": "sequential authentication to multiple engineering workstations",
    "off_hours_or_atypical_ip": "off-hours vendor logons",
}
for flag in case_evidence_flags:
    intel_phrase = mapping.get(flag)
    if intel_phrase:
        matching_docs = [doc_id for doc_id, e in extraction.items()
                         if any(intel_phrase.split()[0] in ind for ind in e["indicators"])]
        case_to_intel_links.append({"case_evidence": flag, "matched_intel_indicator": intel_phrase,
                                     "source_advisories": matching_docs})

result = {
    "corpus_size": len(docs),
    "extraction_per_document": extraction,
    "topics": topics,
    "case_to_intelligence_links": case_to_intel_links,
    "limitations": [
        "Corpus is n=20 synthetic advisories, within the charter's 15-30 target.",
        "Keyword/rule-based extraction is precise but not recall-optimal; topic modelling on a "
        "corpus this size remains indicative rather than a large-scale statistical result.",
    ],
}

with open(f"{OUT}/metrics/nlp_textmining_results.json", "w") as f:
    json.dump(result, f, indent=2)

print(json.dumps(result, indent=2))
