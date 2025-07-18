from bs4 import BeautifulSoup
import requests
from sklearn.naive_bayes import MultinomialNB
import numpy as np
import tkinter as tk
from tkinter import messagebox, font
import tldextract
import time

# --- Helpers ---
def check_ssl(url):
    return url.startswith('https://')

def check_blacklist(url):
    blacklisted_domains = [
        'malicious.com',
        'support-microsoft-helpdesk.cf',
        'update-your-password.amazon.support-alert.net',
        'cards4you.com',
        'fakeprize.net',
        'freeoffer.ru'
    ]
    return any(domain in url for domain in blacklisted_domains)

def check_suspicious_keywords(url):
    suspicious_keywords = ['login', 'secure', 'update', 'account', 'bank', 'verify', 'win', 'free', 'claim', 'gift', 'offer']
    return any(keyword in url.lower() for keyword in suspicious_keywords)

# --- Feature extraction ---
def extract_features(url):
    response_time = 0
    html = "<html></html>"
    failed = False

    try:
        start_time = time.time()
        response = requests.get(url, timeout=5)
        response_time = time.time() - start_time
        html = response.content
    except:
        failed = True
        response_time = 10

    soup = BeautifulSoup(html, 'html.parser') if not failed else BeautifulSoup("<html></html>", 'html.parser')

    iframe_count = len(soup.find_all('iframe')) if not failed else 5
    script_count = len(soup.find_all('script')) if not failed else 10
    link_count = len(soup.find_all('a', href=True)) if not failed else 1
    subdomains = len(tldextract.extract(url).subdomain.split('.'))

    features = [
        min(iframe_count, 10),
        min(script_count, 20),
        min(link_count, 30),
        int(check_ssl(url)),
        int(check_blacklist(url)),
        int(response_time * 10),
        subdomains,
        int(check_suspicious_keywords(url))
    ]
    return features

# --- Classifier (Only Safe and Spam) ---
def classify_webpage(url):
    features = extract_features(url)

    # Updated training data (Safe = 0, Spam = 1)
    X_train = np.array([
        [0, 2, 10, 1, 0, 2, 1, 0],  # Safe
        [0, 1, 8, 1, 0, 1, 1, 0],   # Safe
        [1, 3, 12, 1, 0, 2, 2, 0],  # Safe

        [2, 4, 15, 0, 1, 5, 2, 1],  # Spam
        [3, 5, 10, 0, 1, 4, 3, 1],  # Spam
        [5, 8, 3, 0, 1, 9, 2, 1],   # Spam
        [6, 10, 2, 0, 1, 10, 3, 1], # Spam
        [4, 7, 1, 0, 1, 8, 3, 1],   # Spam
    ])
    y_train = np.array([
        0, 0, 0,  # Safe
        1, 1, 1, 1, 1  # Spam
    ])

    model = MultinomialNB()
    model.fit(X_train, y_train)

    features = np.array(features).reshape(1, -1)
    prediction = model.predict(features)

    label_map = {0: "Safe", 1: "Spam"}
    return label_map[prediction[0]]

# --- GUI ---
def create_gui():
    root = tk.Tk()
    root.title("Webpage Classifier")
    root.geometry("800x800")
    root.config(bg="#2C3E50")

    title_font = font.Font(family="Helvetica", size=35, weight="bold")
    label_font = font.Font(family="Helvetica", size=18)
    button_font = font.Font(family="Helvetica", size=15, weight="bold")

    tk.Label(root, text="Webpage Classifier", font=title_font, fg="white", bg="#2C3E50").pack(pady=20)
    tk.Label(root, text="Enter URL:", font=label_font, fg="white", bg="#2C3E50").pack(pady=5)

    url_entry = tk.Entry(root, width=40, font=("Arial", 20))
    url_entry.pack(pady=5)

    def classify():
        url = url_entry.get()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL")
            return
        result = classify_webpage(url)
        messagebox.showinfo("Classification Result", f"The webpage is classified as: {result}")

    tk.Button(root, text="Classify Webpage", font=button_font, fg="white", bg="#E74C3C",
              padx=20, pady=5, command=classify).pack(pady=20)

    root.mainloop()

# --- Run ---
if __name__ == "__main__":
    create_gui()

