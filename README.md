# CyberSphere Practical Starter

A beginner-friendly, runnable implementation of the CyberSphere architecture:
CTI JSON -> preprocessing -> knowledge graph -> threat-actor analysis -> dashboard.

## Requirements
- Python 3.10+ (Python 3.11 recommended)
- Internet is only needed for the optional MITRE ATT&CK download step.
- Works locally in VS Code on Windows.

## 1. Open the folder
Extract this ZIP, then open `CyberSphere_Practical_Starter` in VS Code.

## 2. Create a virtual environment (Windows PowerShell)
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```
If PowerShell blocks activation, use Command Prompt:
```bat
py -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements.txt
```

## 3. Run the knowledge graph
```powershell
python src\build_graph.py
```
This loads `data/threat_data.json`, builds a NetworkX graph, prints node/edge counts and runs a basic APT29 analysis.

## 4. Run the dashboard
```powershell
streamlit run app.py
```
Your browser should open the local dashboard. If it does not, visit `http://localhost:8501`.

## 5. Add real public MITRE ATT&CK data (optional)
```powershell
python src\download_attack.py
```
This downloads the official Enterprise ATT&CK STIX 2.1 JSON file from the MITRE-maintained repository into `data/enterprise-attack.json`.
Then run:
```powershell
python src\import_attack.py
```
This converts ATT&CK techniques and groups into a simplified CSV for inspection at `data/attack_techniques.csv`.
The starter importer intentionally imports techniques/groups and does not claim that every actor-technique relationship is fully reconstructed. Use the official STIX relationship objects for that in a later enhancement.

## How this maps to the architecture
1. CTI Sources: the current JSON dataset; optional MITRE ATT&CK STIX JSON.
2. Collect & Preprocess: download script and basic normalization in the graph builder.
3. Extract & Resolve: current starter uses explicit structured records; NLP-based extraction is a future extension.
4. Knowledge Graph: NetworkX nodes and typed edges.
5. Threat Analysis: actor-neighbour analysis and confidence/evidence display.
6. Analyst View: Streamlit dashboard.

## Important research honesty
The supplied JSON is a small demo dataset. It is not a verified real-world incident dataset.
The dashboard does not perform machine-learning prediction. NLP extraction, entity resolution, temporal reasoning, NVD API ingestion, and advanced attack-path prediction are extension tasks.
