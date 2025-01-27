import re
from email import message_from_string
from typing import List, Dict

def is_suspicious_url(url: str) -> bool:
    """Check if a URL is suspicious based on common phishing patterns."""
    suspicious_keywords = ['login', 'verify', 'update', 'secure', 'bank', 'password']
    try:
        domain = re.findall(r'https?://([^/]+)', url)[0]
        for keyword in suspicious_keywords:
            if keyword in domain.lower():
                return True
    except IndexError:
        return False
    return False

def analyze_email_headers(headers: Dict[str, str]) -> List[str]:
    """Analyze email headers to identify suspicious patterns."""
    warnings = []
    if 'From' in headers:
        email_match = re.search(r'<(.+?)>', headers['From'])
        if email_match:
            sender_email = email_match.group(1)
            domain = sender_email.split('@')[-1]
            if domain not in ['trusted-domain.com', 'example.com']:
                warnings.append(f"Sender domain '{domain}' is not in the trusted list.")
    
    if 'Received' in headers:
        received_headers = headers['Received']
        if 'unknown' in received_headers.lower():
            warnings.append("Email passed through unknown servers.")

    if 'Reply-To' in headers:
        if headers['From'] != headers['Reply-To']:
            warnings.append("Reply-To address differs from From address.")
    return warnings

def analyze_email_body(body: str) -> List[str]:
    """Analyze email body content for phishing indicators."""
    warnings = []
    urls = re.findall(r'https?://\S+', body)
    for url in urls:
        if is_suspicious_url(url):
            warnings.append(f"Suspicious URL found: {url}")

    phishing_phrases = [
        'verify your account', 'urgent action required', 'click below to update', 'secure your account'
    ]
    for phrase in phishing_phrases:
        if phrase in body.lower():
            warnings.append(f"Phishing phrase detected: '{phrase}'")

    return warnings

def phishing_email_detector(raw_email: str) -> None:
    """Main function to analyze an email and detect phishing indicators."""
    email = message_from_string(raw_email)

    
    headers = dict(email.items())

   
    body = email.get_payload(decode=True).decode('utf-8', errors='ignore') if email.is_multipart() else email.get_payload()

   
    header_warnings = analyze_email_headers(headers)
    body_warnings = analyze_email_body(body)

   
    print("Phishing Email Analysis Report:\n")

    if header_warnings:
        print("[Header Warnings]")
        for warning in header_warnings:
            print(f"- {warning}")
    else:
        print("No suspicious patterns detected in headers.")

    if body_warnings:
        print("\n[Body Warnings]")
        for warning in body_warnings:
            print(f"- {warning}")
    else:
        print("No suspicious patterns detected in body.")


raw_email_example = """From: support@phishing-site.com
Reply-To: support@scam.com
Subject: Urgent: Account Verification Required
Received: by unknown.server.com;

Dear User,

We noticed suspicious activity on your account. Your account may be at risk. Please verify your information immediately by clicking the link below:

https://phishing-site.com/login?verify

Failure to verify your information will result in temporary suspension of your account.

Thank you for your prompt attention to this matter.

Best regards,
Support Team
"""


phishing_email_detector(raw_email_example)
