# IOC Enricher

A simple Python tool to enrich IPs or domains using the [VirusTotal API](https://virustotal.com).

## 🚀 Features
- Enrich IPs or domains for malicious reputation
- Supports single IOC or list from a file
- Outputs results to a CSV

## 🛠️ Installation
```bash
git clone https://github.com/NerdNithish/ioc-enricher.git
cd ioc-enricher
pip install -r requirements.txt

⚙️ Setup

Create a .env file in the project directory:

VT_API_KEY=your_real_api_key_here

▶️ Usage

Example commands:

python main.py --ip 8.8.8.8
python main.py --domain example.com
python main.py --file sample_iocs.txt
