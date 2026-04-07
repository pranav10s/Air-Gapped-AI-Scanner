🛡️ Air-Gapped AI Vulnerability Scanner
A privacy-first, local Static Application Security Testing (SAST) tool. This scanner performs deep semantic analysis of Python codebases to detect critical vulnerabilities (like Insecure Deserialization and SQL Injection) without an internet connection.

🚀 Key Features
Privacy-First: Designed for air-gapped environments. Your source code never leaves your local machine.

Semantic Analysis: Uses Llama-3-8B to understand code intent, going beyond simple regex-based pattern matching.

RAG Integration: Leverages ChromaDB to retrieve industry-standard OWASP Top 10 mitigations for every detected vulnerability.

Resource Optimized: Configured for local execution on Intel CPU/Arc architectures with custom thread-throttling to maintain system stability.

Batch Processing: Recursively scans entire project directories to identify security flaws in complex architectures.

🧠 Architecture
The system follows a Retrieval-Augmented Generation (RAG) workflow:

Ingestion: Python files are parsed and fed into the Llama-3 inference engine.

Analysis: The model classifies code blocks as SAFE or EXPLOIT based on security expertise.

Augmentation: If a vulnerability is found, the engine queries a local ChromaDB vector store for the relevant OWASP mitigation.

Reporting: A combined report is generated with the vulnerability classification and the official fix.

🛠️ Setup & Installation
1. Requirements
Python 3.10+

Minimum 16GB RAM (Recommended)

Intel CPU / GPU with OpenVINO or Torch support

2. Installation
Bash
# Clone the repository
git clone https://github.com/pranav10s/Air-Gapped-AI-Scanner.git
cd Air-Gapped-AI-Scanner

# Install dependencies
pip install -r requirements.txt
3. Model Preparation
Due to file size restrictions, the Llama-3 weights are not included.

Download the weights from Hugging Face.

Place the weights in the /Models directory.

Ensure your local vector database is populated in the /DB directory.

🔍 Usage
To scan a specific file or perform a batch scan:

Python
# Update target_folder in scanner.py
target_folder = r"D:\your_project_path"

# Run the auditor
python scanner.py
