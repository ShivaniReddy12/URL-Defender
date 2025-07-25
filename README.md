# 🛡️ **URL Defender – Safe & Spam URL Classifier**

**URL Defender** is a lightweight desktop application that helps users **identify whether a URL is Safe or Spam** using a trained machine learning model and web scraping techniques. Built with **Python, Tkinter GUI, BeautifulSoup**, and **Naive Bayes classifier**, this tool is designed to be simple, intuitive, and effective.

---

## 🚀 **Features**

- ✅ Classifies URLs as **Safe** or **Spam**
- 🔒 Checks for **SSL**, **blacklisted domains**, **suspicious keywords**
- 🕷️ Extracts **hidden malicious indicators** like `<script>`, `<iframe>`, and suspicious subdomains
- 🧠 Uses **Naive Bayes** for smart classification
- 💻 Comes with a clean and responsive **GUI** built with Tkinter

---

## 🎯 **How It Works**

1. User enters a URL in the GUI.
2. The app fetches the webpage content using `requests` and parses it using `BeautifulSoup`.
3. It checks for:
   - Number of `<script>`, `<iframe>`, `<a>` tags
   - SSL usage (`https://`)
   - Presence of known spammy words (e.g., `win`, `claim`, `login`)
   - Number of subdomains
   - Known blacklisted domains
4. These features are passed into a **Naive Bayes classifier**.
5. The model returns a classification: **Safe** or **Spam**.

---

## 🧪 **Example URLs**

### ✅ **Safe URLs**
| Website        | URL |
|----------------|-----|
| Google         | `https://www.google.com` |
| Wikipedia      | `https://en.wikipedia.org/wiki/Main_Page` |
| GitHub         | `https://github.com` |
| Python         | `https://www.python.org` |
| LinkedIn       | `https://www.linkedin.com` |

### 🚫 **Spam URLs** (for testing only – do not visit!)
| Scam Type      | URL |
|----------------|-----|
| Fake Gift Card | `https://win-free-gift.cards4you.com` |
| Phishing Bank  | `https://secure-login.bankofupdate.com` |
| Fake Microsoft | `https://support-microsoft-helpdesk.cf/verify` |
| Free iPhone    | `https://free-iphone12.winner-prizes.com` |
| Netflix Scam   | `https://get-netflix-free-trial.site` |

---

## 🌍 **Real-World Use Cases**

- 🧓 **For Non-Tech Users**: Helps users avoid clicking on phishing/spam links in emails and messages.
- 🧑‍🏫 **Educators & Students**: Great tool for teaching web security and phishing awareness.
- 🧑‍💻 **Cybersecurity Enthusiasts**: Quickly test and analyze suspicious URLs.
- 🧑‍🎓 **Academic Projects**: Perfect for demonstrating applied machine learning in cybersecurity.

---

## 🛠️ **Tech Stack**

- **Python 3**
- **Tkinter** (GUI)
- **BeautifulSoup** (HTML parsing)
- **Requests** (web content fetching)
- **Scikit-learn** (Naive Bayes classifier)
- **tldextract** (URL parsing)

---
