required_pkgs <- c("tm", "topicmodels", "jsonlite")
to_install <- setdiff(required_pkgs, rownames(installed.packages()))
if (length(to_install) > 0) {
install.packages(to_install, repos = "https://cloud.r-project.org")
}
set.seed(07)
seed_docs <- list(
"ADV-2026-014" = paste(
"Off-hours vendor logons were observed alongside an atypical source",
"IP for a known vendor account. Credential-dumping utility execution",
"followed authentication, and an archive-staging utility was run on",
"an engineering host shortly afterward."
),
"ADV-2026-021" = paste(
"The local logging service was disabled shortly after logon,",
"consistent with defense evasion. Sequential authentication to",
"multiple engineering workstations was observed, along with an",
"unusual process lineage on the jump host."
),
"ADV-2026-027" = paste(
"An unauthorized setpoint write attempt was recorded on a",
"programmable logic controller. Process value deviation from",
"setpoint followed, with OT protocol traffic outside the",
"historical baseline."
),
"ADV-2026-033" = paste(
"A single-source anomaly was observed without cross-log",
"corroboration from any other telemetry source."
)
)
load_corpus <- function(dir_path, fallback) {
if (dir.exists(dir_path)) {
files <- list.files(dir_path, pattern = "\\.txt$", full.names = TRUE)
if (length(files) > 0) {
docs <- setNames(
lapply(files, function(f) paste(readLines(f, warn = FALSE), collapse = " ")),
tools::file_path_sans_ext(basename(files))
)
message(sprintf("Loaded %d documents from %s", length(docs), dir_path))
return(docs)
}
}
message(sprintf(
"No corpus found in %s — using the %d-document placeholder seed corpus. ",
dir_path, length(fallback)
))
message("Replace with 15-30 real, cited advisories before final submission.")
fallback
}
docs <- load_corpus(corpus_dir, seed_docs)
corpus_dir <- "02_data/raw"
View(load_corpus)
docs <- load_corpus(corpus_dir, seed_docs)
rm(corpus_dir)
corpus_dir <- "02_data/raw/threat_intel"
load_corpus <- function(dir_path, fallback) {
if (dir.exists(dir_path)) {
files <- list.files(dir_path, pattern = "\\.txt$", full.names = TRUE)
if (length(files) > 0) {
docs <- setNames(
lapply(files, function(f) paste(readLines(f, warn = FALSE), collapse = " ")),
tools::file_path_sans_ext(basename(files))
)
message(sprintf("Loaded %d documents from %s", length(docs), dir_path))
return(docs)
}
}
message(sprintf(
"No corpus found in %s — using the %d-document placeholder seed corpus. ",
dir_path, length(fallback)
))
message("Replace with 15-30 real, cited advisories before final submission.")
fallback
}
docs <- load_corpus(corpus_dir, seed_docs)
doc_ids <- names(docs)
getwd()
setwd("path/to/GROUP_T07_GridWatch")
ls
ls()
getwd()
# 2.REPROCESSING
raw_corpus <- VCorpus(VectorSource(unlist(docs)))
suppressPackageStartupMessages({
library(tm)
library(topicmodels)
library(jsonlite)
})
raw_corpus <- VCorpus(VectorSource(unlist(docs)))
meta(raw_corpus, "id") <- doc_ids
clean_corpus <- tm_map(raw_corpus, content_transformer(tolower))
clean_corpus <- tm_map(clean_corpus, removePunctuation)
clean_corpus <- tm_map(clean_corpus, removeNumbers)
clean_corpus <- tm_map(clean_corpus, removeWords, stopwords("en"))
clean_corpus <- tm_map(clean_corpus, stripWhitespace)
View(clean_corpus)
# 3. INDICATOR / TACTIC EXTRACTION (rule-based, MITRE-ATT&CK-for-ICS-style)
tactic_dict <- list(
"Initial Access"             = c("off[- ]?hours vendor logon", "atypical source ip",
"remote access pathway"),
"Credential Access"          = c("credential[- ]?dumping", "credential access"),
"Execution"                  = c("living[- ]?off[- ]?the[- ]?land",
"archive[- ]?staging utility"),
"Defense Evasion"            = c("logging service disabled", "defense evasion"),
"Discovery"                  = c("unusual process lineage", "\\bdiscovery\\b"),
"Lateral Movement"           = c("sequential authentication",
"multiple engineering workstations",
"lateral movement"),
"Collection"                 = c("archive[- ]?staging", "\\bcollection\\b"),
"Inhibit Response Function"  = c("unauthorized setpoint write", "inhibit response"),
"Impair Process Control"     = c("process value deviation",
"impair process control",
"ot protocol traffic")
)
extract_indicators <- function(text, dict) {
text_l <- tolower(text)
hits <- list()
for (tactic in names(dict)) {
pats <- dict[[tactic]]
matched <- pats[vapply(pats, function(p) grepl(p, text_l, perl = TRUE), logical(1))]
if (length(matched) > 0) hits[[tactic]] <- unname(matched)
}
hits
}
View(tactic_dict)
doc_indicators <- lapply(docs, extract_indicators, dict = tactic_dict)
View(doc_indicators)
load_corpus()
corpus_dir <- "02_data/raw/threat_intel"
load_corpus()
docs <- load_corpus(corpus_dir, seed_docs)
View(docs)
rm(docs)
docs <- load_corpus(corpus_dir, seed_docs)
# 4. RULE-BASED TACTIC CLASSIFICATION
classify_doc <- function(hits) {
if (length(hits) == 0) return(NA_character_)
counts <- vapply(hits, length, integer(1))
names(counts)[which.max(counts)]
}
View(classify_doc)
doc_primary_tactic <- vapply(doc_indicators, classify_doc, character(1))
View(tactic_dict)
View(doc_indicators)
docs[["ADV-2026-014"]]
# 5. TF-IDF + LDA TOPIC MODELLING
dtm <- DocumentTermMatrix(clean_corpus, control = list(wordLengths = c(3, Inf)))
dtm <- dtm[, colSums(as.matrix(dtm)) > 0]      # drop empty columns
dtm <- dtm[rowSums(as.matrix(dtm)) > 0, ]       # drop empty rows (safety)
k_topics <- min(2, nrow(dtm) - 1)
if (k_topics >= 2) {
lda_model <- LDA(dtm, k = k_topics, control = list(seed = 42))
top_terms_per_topic <- terms(lda_model, 8)
doc_topics <- topics(lda_model)
topics_out <- lapply(seq_len(k_topics), function(i) {
list(topic = i - 1, top_terms = as.character(top_terms_per_topic[, i]))
})
} else {
message(sprintf(
"Corpus too small for topic modelling (%d usable document(s) after cleaning) - need at least 3. Skipping LDA.",
nrow(dtm)
))
topics_out <- list()
}
View(topics_out)
topics_out[[1]]
# 6. CASE-TO-INTELLIGENCE LINKING
case_evidence <- c(
off_hours_or_atypical_ip    = "vendor account logged on outside normal hours from an unusual source ip",
credential_access_edr_alert = "edr flagged credential dumping activity on an engineering host",
defense_evasion_edr_alert   = "local logging was disabled shortly after the vendor logon",
ot_unauthorized_write       = "an unauthorized write to a plc setpoint was recorded",
lateral_movement_multi_host = "the account authenticated sequentially to several engineering workstations"
)
tokenize <- function(x) unique(tolower(unlist(strsplit(gsub("[^A-Za-z ]", " ", x), "\\s+"))))
jaccard  <- function(a, b) {
a <- tokenize(a); b <- tokenize(b)
if (length(union(a, b)) == 0) return(0)
length(intersect(a, b)) / length(union(a, b))
}
link_case_to_intel <- function(evidence_text, docs, min_score = 0.05) {
scores <- vapply(docs, jaccard, numeric(1), b = evidence_text)
best_idx <- which.max(scores)
if (scores[best_idx] < min_score) {
return(list(matched_doc = NA_character_, score = unname(scores[best_idx])))
}
list(matched_doc = names(scores)[best_idx], score = unname(scores[best_idx]))
}
case_links <- lapply(names(case_evidence), function(ev) {
res <- link_case_to_intel(case_evidence[[ev]], docs)
list(
case_evidence          = ev,
matched_source_advisory = res$matched_doc,
similarity_score        = round(res$score, 3)
)
})
View(case_links)
case_links[[5]]
# 7. CONSOLE SUMMARY
cat("\n--------------- TEXT MINING WORKFLOW SUMMARY ------------------\n")
cat(sprintf("Corpus size: %d documents\n", length(docs)))
cat("\nPer-document primary tactic (rule-based classification):\n")
print(doc_primary_tactic)
cat("\nPer-document extracted indicators:\n")
for (id in names(doc_indicators)) {
cat(sprintf("  %s:\n", id))
if (length(doc_indicators[[id]]) == 0) {
cat("    (no dictionary matches — flagged as low-corroboration)\n")
} else {
for (tac in names(doc_indicators[[id]])) {
cat(sprintf("    [%s] %s\n", tac, paste(doc_indicators[[id]][[tac]], collapse = "; ")))
}
}
}
if (length(topics_out) > 0) {
cat("\nTopic model (k =", k_topics, "):\n")
for (t in topics_out) cat(sprintf("  Topic %d: %s\n", t$topic, paste(t$top_terms, collapse = ", ")))
} else {
cat("\nTopic model: skipped (corpus too small - see message above)\n")
}
cat("\nCase-to-intelligence links:\n")
for (l in case_links) {
cat(sprintf("  %-30s -> %-15s (similarity=%.3f)\n",
l$case_evidence, ifelse(is.na(l$matched_source_advisory), "NO MATCH", l$matched_source_advisory),
l$similarity_score))
}
cat("----------------------------------------------------------------\n\n")
# 8. EXPORT (mirrors the schema of nlp_textmining_results.json)
output <- list(
corpus_size = length(docs),
extraction_per_document = setNames(
lapply(names(doc_indicators), function(id) {
list(
tactics_mentioned = names(doc_indicators[[id]]),
indicators = unname(unlist(doc_indicators[[id]])),
primary_tactic_classification = doc_primary_tactic[[id]]
)
}),
names(doc_indicators)
),
topics = topics_out,
case_to_intelligence_links = case_links,
limitations = c(
if (length(docs) < 15) sprintf(
"Corpus is %d documents against the charter target of 15-30 - results are illustrative, not statistically robust. Populate %s with real advisories and re-run.",
length(docs), corpus_dir
),
"Rule-based tactic classification is precise but not recall-optimal; a trained classifier should replace it once the corpus supports a proper train/test split."
)
)
View(output)
output[["corpus_size"]]
output[["extraction_per_document"]]
output[["topics"]]
output[["case_to_intelligence_links"]]
output[["limitations"]]
out_dir <- "06_text_mining"
if (!dir.exists(out_dir)) dir.create(out_dir, recursive = TRUE)
out_path <- file.path(out_dir, "nlp_textmining_results_R.json")
write_json(output, out_path, auto_unbox = TRUE, pretty = TRUE)
cat(sprintf("Results written to %s\n", out_path))
