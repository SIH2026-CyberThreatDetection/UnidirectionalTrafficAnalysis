# Technical Report: Feature Engineering & Dataset Pipeline

**Module:** `src/02_feature_dataset`  
**Objective:** Architecture documentation for the data transformation layer, responsible for converting normalized telemetry into a strictly passive, machine-learning-ready feature matrix without relying on payload decryption.

## Pipeline Overview
The `02_feature_dataset` directory is the core processing engine that guarantees compliance with the SIH 26145 "no payload decryption" constraint. It takes the standardized flow records from the M1 ingestion layer and mathematically extracts behavioral, volumetric, and protocol-specific metadata (our 12-Feature Golden Schema) to train the downstream AI models.

## Component Breakdown

### 1. Data Sanitization & Structuring
Raw network data inherently contains noise, infinite calculations, and temporal biases. These scripts prepare the foundation.
* **`clean.py`**: The sanitization module. It strips out malformed rows, handles missing values (NaNs), and caps infinite calculations (like `Flow Bytes/s` when duration is technically zero), ensuring the data matrix won't crash the XGBoost model.
* **`split.py`**: Enforces a strict chronological train/test split. Rather than randomly shuffling packets, it splits data temporally to mathematically guarantee the AI is evaluated on forward-facing, unseen network conditions, preventing data leakage.

### 2. Specialized Feature Extraction
These modules mathematically summarize network behavior into distinct columns without ever looking at the packet payload.
* **`flow_features.py`**: Extracts baseline volumetric statistics, calculating structural metrics such as `Total Packets`, `Flow Duration`, `Flow Bytes/s`, and `Packet Length Mean`.
* **`dns_features.py`**: Targets Category 3 (DNS Tunneling) and DGA threats by engineering highly discriminative metadata features, specifically calculating `dns_query_length` and `dns_entropy`.
* **`extract_tls.py` & `tls_features.py`**: Designed to handle Category 4 (Encrypted Malware). These scripts analyze the unencrypted handshakes of TLS sessions, extracting metadata like certificate validity, issuer anomalies, and cipher suite selections to profile encrypted threats.

### 3. Data Augmentation
Standard benchmark datasets often lack sufficient examples of highly specific modern attacks.
* **`generate_dns_tunnels.py`**: A synthetic data generator. It injects mathematically accurate DNS tunneling signatures into the baseline dataset to resolve class imbalances, ensuring the AI has a concrete signature baseline to learn from.

### 4. Orchestration & Validation
These scripts automate the end-to-end execution of the feature engineering phase.
* **`merge_datasets.py`**: Fuses the disparate feature subsets (Flow, DNS, TLS, and Synthetic) into a single, cohesive dataset, aligning everything to a unified index.
* **`pipeline.py`**: The master execution script. It orchestrates the entire `02_feature_dataset` workflow sequentially, allowing the team to rebuild the entire ML feature matrix with a single terminal command.
* **`generate_reports.py`**: An automated profiling tool that generates data quality checks and distribution statistics (e.g., verifying class balances and feature ranges) before the final CSV is handed off to the M3 machine learning pipeline.
