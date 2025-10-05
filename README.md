# IOC Enricher

A simple Python tool to enrich IPs or domains using the [VirusTotal API](https://virustotal.com).

**Status:** Week 1 MVP — functional core features, more coming soon 🚀
> This is an **open-source MVP** — contributions, issues, and feedback are welcome!

## 🚀 Features
- Enrich IPs or domains for malicious reputation
- Supports single IOC or list from a file
- Outputs results to a CSV

## 🛠️ Installation

Clone the repo and install dependencies:

```bash
git clone https://github.com/NerdNithish/ioc-enricher.git
cd ioc-enricher
pip install -r requirements.txt
```

## ⚙️ Setup

Create a `.env` file in the project directory with your VirusTotal API key:

```
VT_API_KEY=your_real_api_key_here
```

Make sure `.env` is **not committed** (it’s in `.gitignore`).

## ▶️ Usage

Run the script with examples:

```bash
python main.py --ip 8.8.8.8
python main.py --domain example.com
python main.py --file sample_iocs.txt
```

## 📂 Output

- Results are saved to `enriched_iocs.csv` in the project folder.

## 📜 License
This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

## 🗺️ Roadmap
- [ ] Add support for URL enrichment
- [ ] Handle both IPs **and** domains in file input
- [ ] Parallel requests with rate-limit handling
- [ ] Dockerfile for containerized usage

## 🤝 Contributing
Pull requests and issues are welcome!  
For major changes, please open an issue first to discuss.
