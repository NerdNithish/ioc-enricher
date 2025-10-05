# IOC Enricher

A simple Python tool to enrich IPs or domains using the [VirusTotal API](https://virustotal.com).

**Status:** Week 1 MVP — functional core features, more coming soon 🚀

Built as a learning project + practical wedge for threat intelligence automation.
> This is an **open-source MVP** — contributions, issues, and feedback are welcome!

---

## ✨ Features

- Enrich **IP addresses** (ASN, country, malicious votes, etc.)
- Enrich **domains** (registrar, whois, malicious votes, etc.)
- Batch enrichment from a file (one IOC per line)
- Outputs results to **CSV** for easy SOC workflows
- Built-in error handling + rate-limit pauses for free API tier

---

## 🚀 Installation

Clone the repo:

```bash
git clone https://github.com/NerdNithish/ioc-enricher.git
cd ioc-enricher
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 🔑 Setup

1. Get a free VirusTotal API key: [https://www.virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)  
2. Create a `.env` file in the project root:

```
VT_API_KEY=your_api_key_here
```

> **Note:** `.env` is ignored by Git and never pushed — your API key stays private.

---

## 🖥️ Usage

Enrich a single IP:

```bash
python main.py --ip 8.8.8.8
```

Enrich a single domain:

```bash
python main.py --domain example.com
```

Enrich from a file (`sample_iocs.txt` with one IOC per line):

```bash
python main.py --file sample_iocs.txt
```

Results are saved in `enriched_iocs.csv`.

---

## 📂 Example Output

| type   | ioc         | malicious | suspicious | harmless | country | asn       | last_analysis_date |
| ------ | ----------- | --------- | ---------- | -------- | ------- | --------- | ----------------- |
| ip     | 8.8.8.8     | 0         | 0          | 80       | US      | Google    | 1706723821        |
| domain | example.com | 2         | 1          | 72       | US      | Namecheap | 1706711120        |

---

## 📝 Roadmap

- [ ] Add hash enrichment (MD5/SHA256)
- [ ] Integrate AbuseIPDB + OTX for cross-checking
- [ ] Add simple scoring system
- [ ] Colored CLI output for quick analysis
- [ ] Dockerfile for containerized usage
- [ ] Handle both IPs and domains in file input

---

## ⚠️ Disclaimer

This tool uses the **free VirusTotal public API** — subject to strict rate limits.  
It’s for **educational + personal use** only. Not intended for production SOCs without a proper API license.

---

## 💡 Contributing

Pull requests, issues, and feedback are welcome!  
For major changes, please open an issue first to discuss.  

---

## 📖 Blog Post

This project is part of my journey documenting **AI vs AI in Cybersecurity**.  
Read the full story here 👉 https://medium.com/meetcyber/why-im-starting-this-cybersecurity-blog-in-my-final-year-576155377e9c
