import re

# ----------------------------
# Phishing Detection Function
# ----------------------------
def analyze_email(email):

    red_flags = []
    risk_score = 0

    suspicious_keywords = [
        "urgent",
        "verify",
        "password",
        "bank",
        "login",
        "account suspended",
        "click here",
        "confirm",
        "winner",
        "free",
        "security alert",
        "update account",
        "reset password",
        "hr policy",
        "meeting invitation",
        "questionnaire"
    ]

    # Keyword Detection
    for keyword in suspicious_keywords:
        if keyword.lower() in email.lower():
            red_flags.append(f"Suspicious keyword: {keyword}")
            risk_score += 1

    # URL Detection
    urls = re.findall(r'https?://\S+|www\.\S+', email)

    if urls:
        red_flags.append("Contains link(s)")
        risk_score += 2

        for url in urls:

            if any(shortener in url.lower() for shortener in
                   ["bit.ly", "tinyurl", "goo.gl"]):
                red_flags.append(f"URL Shortener Detected: {url}")
                risk_score += 2

            if any(word in url.lower() for word in
                   ["login", "verify", "update", "secure", "bank"]):
                red_flags.append(f"Suspicious URL: {url}")
                risk_score += 2

    # Sender Mismatch
    if "@" in email and ("gmail.com" in email.lower() or
                         "yahoo.com" in email.lower()):
        red_flags.append("Possible Sender-Domain Mismatch")
        risk_score += 1

    # Urgency Detection
    urgency_words = [
        "immediately",
        "urgent",
        "within 24 hours",
        "act now",
        "limited time"
    ]

    for word in urgency_words:
        if word.lower() in email.lower():
            red_flags.append(f"Urgency Trigger: {word}")
            risk_score += 1

    # Password Request
    if "password" in email.lower():
        red_flags.append("Password Request Detected")
        risk_score += 2

    # QR Code Detection
    if "qr code" in email.lower() or "scan code" in email.lower():
        red_flags.append("QR Code Phishing Attempt")
        risk_score += 2

    # Callback Scam
    if "call us" in email.lower() or "support number" in email.lower():
        red_flags.append("Possible Callback Scam")
        risk_score += 2

    # Deepfake Mention
    if "video call" in email.lower() or "voice call" in email.lower():
        red_flags.append("Possible Deepfake/Social Engineering Attempt")
        risk_score += 2

    # Classification
    if risk_score <= 2:
        classification = "SAFE"
        action = "CLOSE"

    elif risk_score <= 5:
        classification = "SUSPICIOUS"
        action = "WARN USER"

    else:
        classification = "MALICIOUS"
        action = "BLOCK & ESCALATE"

    # Report
    print("\n===== PHISHING TRIAGE REPORT =====")

    print(f"\nRisk Score: {risk_score}")

    print(f"\nClassification: {classification}")

    print(f"\nRecommended Action: {action}")

    print("\nRed Flags Found:")

    if red_flags:
        for flag in red_flags:
            print("-", flag)
    else:
        print("No red flags detected.")

    print("\nWhy Unsafe:")

    if classification == "SAFE":
        print("No significant phishing indicators detected.")

    elif classification == "SUSPICIOUS":
        print("Some phishing indicators were detected. User verification is recommended.")

    else:
        print("Multiple phishing indicators detected. Message may be malicious and should be blocked.")


# ----------------------------
# Main Program
# ----------------------------
while True:

    print("\n==========================================")
    print(" AI-Powered Phishing Email Detection System")
    print("==========================================")

    email_text = input("\nPaste Email Message:\n")

    analyze_email(email_text)

    choice = input("\nAnalyze another email? (yes/no): ").strip().lower()

    if choice != "yes":
        print("\nThank you for using the system.")
        break