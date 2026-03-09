# train_models.py - Enhanced ML Model Training
import os, joblib, re
import pandas as pd, numpy as np
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score
from urllib.parse import urlparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
import warnings

warnings.filterwarnings('ignore')

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
os.makedirs(MODEL_DIR, exist_ok=True)

# Try loading suspicious keywords dataset for training; fall back to default list

def load_suspicious_keywords(csv_path):
    try:
        df = pd.read_csv(csv_path)
        if "SUSPICIOUS_KEYWORDS" in df.columns:
            return df["SUSPICIOUS_KEYWORDS"].astype(str).tolist()
    except Exception as e:
        print(f"Warning: failed to read suspicious keywords csv: {e}")
    return []

KEYWORDS_CSV = os.path.join(os.path.dirname(__file__), "suspicious_keywords_1_million.csv")

SUSPICIOUS_KEYWORDS = load_suspicious_keywords(KEYWORDS_CSV) or [
    "login", "bank", "verify", "secure", "password", "update", "account", "confirm",
    "paypal", "amazon", "facebook", "google", "microsoft", "free", "gift", "bonus",
    "win", "prize", "reward", "click", "security", "authenticate", "validation",
    "unlock", "recover", "billing", "payment", "credit", "debit", "card"
]


def extract_features_from_url(url):
    """Enhanced feature extraction for training"""
    f = {}
    try:
        f["length"] = len(url)
        f["dots"] = url.count(".")
        f["digits"] = sum(c.isdigit() for c in url)
        f["digit_ratio"] = f["digits"] / max(1, f["length"])
        f["has_https"] = 1 if url.lower().startswith("https://") else 0
        f["has_ip"] = 1 if re.search(r"https?://\d+\.\d+\.\d+\.\d+", url) else 0
        f["special_chars"] = len(re.findall(r'[^a-zA-Z0-9\.\-]', url))

        low = url.lower()
        f["suspicious_keywords_count"] = sum(1 for k in SUSPICIOUS_KEYWORDS if k in low)

        p = urlparse(url)
        f["path_len"] = len(p.path or "")
        f["query_len"] = len(p.query or "")
        f["hostname_len"] = len(p.hostname or "")
        f["num_subdomains"] = p.hostname.count(".") - 1 if p.hostname else 0

        # Calculate entropy
        hostname = p.hostname or ""
        if hostname:
            prob = [float(hostname.count(c)) / len(hostname) for c in set(hostname)]
            import math
            f["entropy"] = -sum(p * math.log2(p) for p in prob)
        else:
            f["entropy"] = 0

    except:
        f = dict(length=0, dots=0, digits=0, digit_ratio=0, has_https=0, has_ip=0,
                 special_chars=0, suspicious_keywords_count=0, path_len=0,
                 query_len=0, hostname_len=0, num_subdomains=0, entropy=0)
    return f


def build_dataset_from_csv(path):
    """Build dataset from CSV file"""
    df = pd.read_csv(path)

    # Handle different column names
    if "label" not in df.columns:
        if "status" in df.columns:
            df["label"] = df["status"]
        elif "malicious" in df.columns:
            df["label"] = df["malicious"]
        else:
            raise ValueError("No label column found")

    # Convert labels to binary
    if df["label"].dtype == object:
        df["label"] = df["label"].map(
            lambda x: 1 if str(x).lower() in ["malicious", "phishing", "1", "true", "yes"] else 0
        )

    # Extract features
    feats = df["url"].apply(extract_features_from_url).tolist()
    X = pd.DataFrame(feats)
    y = df["label"].astype(int).values

    return X, y


def generate_synthetic_dataset(n=2000):
    """Generate synthetic dataset for training"""
    urls = []
    labels = []

    # Safe URLs
    safe_patterns = [
        "https://www.{}.com",
        "https://{}.org/about",
        "https://blog.{}.net/posts/{}",
        "https://{}.edu/department/{}"
    ]

    # Malicious URLs
    malicious_patterns = [
        "http://{}-login-secure.com/verify",
        "http://bank-update-{}.com/login?id={}",
        "https://free-gift-{}.win/claim",
        "http://{}.update-account.com/secure"
    ]

    for i in range(n):
        if i % 2 == 0:  # Safe URLs
            pattern = np.random.choice(safe_patterns)
            domain = f"example{i}"
            url = pattern.format(domain, i)
            labels.append(0)
        else:  # Malicious URLs
            pattern = np.random.choice(malicious_patterns)
            domain = f"secure{i}"
            url = pattern.format(domain, i)
            labels.append(1)
        urls.append(url)

    X = pd.DataFrame([extract_features_from_url(u) for u in urls])
    y = np.array(labels)

    return X, y, urls


def train_and_evaluate_model(X, y, model_name):
    """Train and evaluate XGBoost model"""
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train XGBoost model
    model = XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric='logloss'
    )

    model.fit(X_train_scaled, y_train)

    # Evaluate
    y_pred = model.predict(X_test_scaled)
    y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]

    accuracy = accuracy_score(y_test, y_pred)
    auc_score = roc_auc_score(y_test, y_pred_proba)

    print(f"\n📊 {model_name} Model Performance:")
    print(f"✅ Accuracy: {accuracy:.4f}")
    print(f"📈 AUC Score: {auc_score:.4f}")
    print("\n📋 Classification Report:")
    print(classification_report(y_test, y_pred))

    # Save model and scaler
    joblib.dump(model, os.path.join(MODEL_DIR, f"{model_name}.joblib"))
    joblib.dump(scaler, os.path.join(MODEL_DIR, f"{model_name}_scaler.joblib"))

    return model, scaler


def main():
    print("🔮 Training ML Models for URL Security...")

    # Try to load dataset from CSV
    CSV_PATH = os.path.join(os.path.dirname(__file__), "url_dataset_100k.csv")

    if os.path.exists(CSV_PATH):
        print("📁 Loading dataset from CSV...")
        X, y = build_dataset_from_csv(CSV_PATH)
        print(f"✅ Loaded {len(y)} samples from CSV")
    else:
        print("📝 Generating synthetic dataset...")
        X, y, urls = generate_synthetic_dataset(2000)
        print(f"✅ Generated {len(y)} synthetic samples")

    print(f"\n📊 Dataset Balance:")
    print(f"🔴 Malicious: {sum(y)}")
    print(f"🟢 Benign: {len(y) - sum(y)}")

    # Train Detection Model (Current Threats)
    print("\n" + "=" * 50)
    print("🎯 Training REAL-TIME DETECTION Model...")
    detect_model, detect_scaler = train_and_evaluate_model(X, y, "detect_xgb")

    # Train Prediction Model (Future Threats)
    print("\n" + "=" * 50)
    print("🔮 Training FUTURE PREDICTION Model...")

    # Create future risk labels (more aggressive)
    future_y = np.array([
        1 if yi == 1 or (np.random.rand() < 0.2 and xi['suspicious_keywords_count'] > 0) else 0
        for yi, xi in zip(y, X.to_dict('records'))
    ])

    predict_model, predict_scaler = train_and_evaluate_model(X, future_y, "predict_xgb")

    print("\n🎉 Model Training Completed!")
    print(f"📁 Models saved to: {MODEL_DIR}")
    print(f"🔍 Detection Model: detect_xgb.joblib")
    print(f"🔮 Prediction Model: predict_xgb.joblib")


if __name__ == "__main__":
    main()