# SSH Log Analysis and Threat Hunting Exercise:

# Overview:
This project presents a threat-hunting analysis of a public SSH Honeypot Interaction Dataset using Python and pandas.

# Objective:
The objective was to identify suspicious SSH activity, investigate the related evidence, document the findings, and recommend appropriate next actions.

# Tools Used:
1. Python.
2. Pandas.
3. MITRE ATT&CK Framework.
4. MITRE ATT&CK Navigator.

# Dataset:
SSH Honeypot Interaction Dataset from Zenodo:

https://zenodo.org/records/20435481

# Threat Hunting Findings:
Four suspicious activity patterns were identified:

1. Suspicious Post-Login Activity.
2. High-Volume and Rapid SSH Connection Activity.
3. Repeated Credential Attempts from Multiple Source IPs.
4. Off-Peak Automated SSH Credential-Guessing Activity.

# Automated Threat Hunting:
A Python-based automated threat-hunting script was developed to detect the identified suspicious activity patterns using predefined detection rules.

# MITRE ATT&CK Mapping:
Relevant findings were mapped to applicable MITRE ATT&CK techniques, and the mappings were visualized using MITRE ATT&CK Navigator.

# Files:
- [Automated_Threat_Hunting.py](Automated_Threat_Hunting.py)
- [Threat_Hunting_Log_Analysis.ipynb](Threat_Hunting_Log_Analysis.ipynb)
- [Threat_Hunting_Report.pdf](Threat_Hunting_Report.pdf)
