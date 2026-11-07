# SOC Alert Triage — Build Checklist

> Companion to the [`README.md`](README.md) — these phases mirror the approach documented there. Keep the two in sync if scope changes.

> Do Phase 1–4 end-to-end with **one rule** first, then expand. A working narrow pipeline beats a half-built wide one.

## Phase 0 — Setup

- [X] Create GitHub repo, add `README.md` stub and `.gitignore` (ignore `data/`)
- [X] Set up Python env (pandas, numpy, matplotlib; streamlit optional)
- [X] Add `requirements.txt`

## Phase 1 — Get & clean the data

- [X] Download the **`GeneratedLabelledFlows`** version of CIC-IDS2017 (has Source IP + Timestamp)
- [X] Pull Tuesday (brute force) and Wednesday (DoS) + Monday (benign baseline)
- [X] Strip leading spaces from column names
- [X] Replace `inf` with `NaN`, handle missing values
- [X] Drop the duplicate `Fwd Header Length.1` column

## Phase 2 — Baseline

- [X] Load Monday (all benign)
- [X] Compute per-port percentiles for: packet rate, flow duration, byte rate, IAT
- [X] Save/print thresholds each rule will use

## Phase 3 — Detection rules

- [X] **Brute force:** candidate filter (auth ports, small/short flows) → attempts-per-source-per-minute
- [X] **DoS flood:** port 80 + high packet rate (Hulk, GoldenEye)
- [X] **DoS low-and-slow:** long duration + near-zero throughput + high IAT (slowloris, Slowhttptest)
- [X] Confirm all thresholds come from the baseline, not hardcoded numbers

## Phase 4 — Generate & score alerts

- [X] Run rules across Tuesday/Wednesday to produce the alert set
- [X] Score each rule vs. labels: TP / FP / FN, precision, recall
- [X] Tune each rule/threshold to try and achieve a higher recall without collapsing precision.

## Phase 5 — Triage analytics

- [X] Alert volume over time (by hour, by attack type)
- [X] False-positive rate per rule + signal-to-noise ranking
- [X] Noisiest sources / destinations
- [X] Priority score to sort the queue
- [X] The tuning tradeoff: "drop the noisiest rule → how much coverage is lost?"

## Phase 6 — Dashboard

- [X] Build in Splunk (reinforces certs) **and/or** Streamlit (browser-clickable)
- [X] Capture a screenshot for the README

## Phase 7 — Write-up

- [X] Finish README: fill in the results numbers + dashboard screenshot
- [X] (Optional) MITRE ATT&CK mapping table
- [X] Draft the resume bullet with your real numbers
- [X] Push, clean commit history, confirm README renders

## Stretch

- [ ] Extend to Thursday (web attacks) / Friday (DDoS, port scan, botnet)
- [ ] Group alerts into incidents (campaign view)
- [ ] Mock SLA metrics (mean time to acknowledge / triage)
