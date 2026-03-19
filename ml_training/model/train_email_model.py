"""
train_email_model.py — BrowserShield ML Training Script
=========================================================
Trains a phishing email detection model on the SpamAssassin dataset.

What this script does:
  1. Loads and cleans the dataset
  2. Engineers features (TF-IDF)
  3. Trains and compares 3 models
  4. Evaluates with full metrics (accuracy, precision, recall, F1, ROC-AUC)
  5. Saves the best model and vectorizer to /models/

Run from the ml_training/ folder:
    python train_email_model.py

Output files:
    ../models/email_model.pkl
    ../models/vectorizer.pkl
    ../models/evaluation_report.txt
"""

import os
import pickle
import warnings
warnings.filterwarnings("ignore")

import pandas as pd
import numpy as np

from sklearn.model_selection   import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model      import LogisticRegression
from sklearn.ensemble          import RandomForestClassifier
from sklearn.svm               import LinearSVC
from sklearn.calibration       import CalibratedClassifierCV
from sklearn.metrics           import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix,
    classification_report
)

# ─────────────────────────────────────────────
#  PATHS
# ─────────────────────────────────────────────

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "dataset", "SpamAssasin.csv")
MODEL_DIR    = os.path.join(BASE_DIR, "../models")
REPORT_PATH  = os.path.join(MODEL_DIR, "evaluation_report.txt")

os.makedirs(MODEL_DIR, exist_ok=True)


# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────

def separator(char="─", width=60):
    print(char * width)

def section(title):
    print()
    separator()
    print(f"  {title}")
    separator()


# ─────────────────────────────────────────────
#  STEP 1: LOAD DATASET
# ─────────────────────────────────────────────

section("STEP 1: Loading Dataset")

if not os.path.exists(DATASET_PATH):
    raise FileNotFoundError(
        f"Dataset not found at: {DATASET_PATH}\n"
        f"Expected location: ml_training/dataset/SpamAssasin.csv"
    )

data = pd.read_csv(DATASET_PATH)

print(f"  Loaded: {len(data):,} rows")
print(f"  Columns: {list(data.columns)}")
print(f"  Shape: {data.shape}")


# ─────────────────────────────────────────────
#  STEP 2: CLEAN AND PREPARE DATA
# ─────────────────────────────────────────────

section("STEP 2: Cleaning Data")

# Combine subject + body into one text field
# Subject is repeated twice to give it more weight — it's often the
# strongest signal for phishing (urgent/misleading subject lines)
data["text"] = (
    data.get("subject", pd.Series([""] * len(data))).fillna("") + " " +
    data.get("subject", pd.Series([""] * len(data))).fillna("") + " " +
    data.get("body",    pd.Series([""] * len(data))).fillna("")
)

# Normalize labels — handle various formats in the dataset
data["label"] = data["label"].astype(str).str.lower().str.strip()

print(f"  Raw label values found: {data['label'].unique()}")

label_map = {
    "spam":       1,
    "phishing":   1,
    "1":          1,
    "ham":        0,
    "legitimate": 0,
    "safe":       0,
    "0":          0,
}

y = data["label"].map(label_map)

# Drop rows with unmapped/unknown labels
before = len(data)
mask   = ~y.isna()
data   = data[mask].reset_index(drop=True)
y      = y[mask].reset_index(drop=True).astype(int)
after  = len(data)

print(f"  Dropped unmapped rows: {before - after}")
print(f"  Final dataset size: {after:,} samples")

# Check class distribution
phishing_count = int(y.sum())
safe_count     = after - phishing_count
print(f"  Class distribution:")
print(f"    Phishing / Spam (1): {phishing_count:,} ({phishing_count/after*100:.1f}%)")
print(f"    Safe / Ham      (0): {safe_count:,}  ({safe_count/after*100:.1f}%)")

# Warn about class imbalance
ratio = max(phishing_count, safe_count) / max(min(phishing_count, safe_count), 1)
if ratio > 3:
    print(f"\n  ⚠ Class imbalance detected (ratio {ratio:.1f}:1)")
    print(f"    Using class_weight='balanced' to compensate")

X = data["text"]


# ─────────────────────────────────────────────
#  STEP 3: FEATURE ENGINEERING (TF-IDF)
# ─────────────────────────────────────────────

section("STEP 3: TF-IDF Feature Extraction")

# TF-IDF with unigrams and bigrams
# Bigrams catch patterns like "click here", "verify account", "urgent action"
vectorizer = TfidfVectorizer(
    stop_words   = "english",
    max_features = 8000,         # increased from 5000
    ngram_range  = (1, 2),       # unigrams + bigrams
    min_df       = 2,            # ignore very rare terms
    sublinear_tf = True          # log normalization for term frequency
)

X_vec = vectorizer.fit_transform(X)

print(f"  Vocabulary size: {len(vectorizer.vocabulary_):,} features")
print(f"  Matrix shape: {X_vec.shape}")
print(f"  Using: unigrams + bigrams, log-TF normalization")

# Show top 10 most informative features
feature_names = vectorizer.get_feature_names_out()
print(f"\n  Top 10 vocabulary examples (not ranked): "
      f"{list(feature_names[:5])} ... {list(feature_names[-5:])}")


# ─────────────────────────────────────────────
#  STEP 4: TRAIN/TEST SPLIT
# ─────────────────────────────────────────────

section("STEP 4: Train / Test Split")

X_train, X_test, y_train, y_test = train_test_split(
    X_vec, y,
    test_size    = 0.2,
    random_state = 42,
    stratify     = y        # ensures both splits have same class ratio
)

print(f"  Training set: {X_train.shape[0]:,} samples")
print(f"  Test set:     {X_test.shape[0]:,} samples")
print(f"  Stratified split: ✓ (class ratio preserved in both sets)")


# ─────────────────────────────────────────────
#  STEP 5: TRAIN AND COMPARE 3 MODELS
# ─────────────────────────────────────────────

section("STEP 5: Training & Comparing Models")

# Define 3 candidate models
candidates = {
    "Logistic Regression": LogisticRegression(
        max_iter     = 1000,
        class_weight = "balanced",
        C            = 1.0,
        solver       = "lbfgs"
    ),
    "Random Forest": RandomForestClassifier(
        n_estimators = 100,
        class_weight = "balanced",
        random_state = 42,
        n_jobs       = -1
    ),
    # LinearSVC doesn't support predict_proba natively
    # CalibratedClassifierCV wraps it to add probability output
    "Linear SVM": CalibratedClassifierCV(
        LinearSVC(
            max_iter     = 2000,
            class_weight = "balanced",
            C            = 1.0
        )
    )
}

results      = {}
trained_models = {}

print(f"\n  {'Model':<25} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1':>10} {'ROC-AUC':>10}")
print(f"  {'─'*25} {'─'*10} {'─'*10} {'─'*10} {'─'*10} {'─'*10}")

for name, clf in candidates.items():
    # Train
    clf.fit(X_train, y_train)
    trained_models[name] = clf

    # Predict
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    # Metrics
    acc  = accuracy_score(y_test,  y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test,    y_pred, zero_division=0)
    f1   = f1_score(y_test,        y_pred, zero_division=0)
    auc  = roc_auc_score(y_test,   y_prob)

    results[name] = {
        "model":     clf,
        "accuracy":  acc,
        "precision": prec,
        "recall":    rec,
        "f1":        f1,
        "roc_auc":   auc,
        "y_pred":    y_pred,
        "y_prob":    y_prob
    }

    print(f"  {name:<25} {acc:>9.3f}  {prec:>9.3f}  {rec:>9.3f}  {f1:>9.3f}  {auc:>9.3f}")


# ─────────────────────────────────────────────
#  STEP 6: SELECT BEST MODEL
# ─────────────────────────────────────────────

section("STEP 6: Selecting Best Model")

# Select by F1 score — best balance of precision and recall
best_name = max(results, key=lambda k: results[k]["f1"])
best      = results[best_name]

print(f"  Best model: {best_name}")
print(f"  Selected by: highest F1 score ({best['f1']:.4f})")
print()

# Why F1 and not just accuracy?
print("  Why F1 score for selection:")
print("  ─ Accuracy alone is misleading with class imbalance")
print("  ─ Precision = how many flagged are actually phishing")
print("  ─ Recall    = how many phishing emails we catch")
print("  ─ F1        = harmonic mean of both — best single metric")


# ─────────────────────────────────────────────
#  STEP 7: DETAILED EVALUATION OF BEST MODEL
# ─────────────────────────────────────────────

section("STEP 7: Detailed Evaluation — " + best_name)

y_pred = best["y_pred"]
y_prob = best["y_prob"]

# Confusion matrix
cm = confusion_matrix(y_test, y_pred)
tn, fp, fn, tp = cm.ravel()

fpr = fp / max(fp + tn, 1)   # False positive rate
fnr = fn / max(fn + tp, 1)   # False negative rate (missed phishing)

print(f"\n  Confusion Matrix:")
print(f"  ┌─────────────────────────────────────┐")
print(f"  │              Predicted               │")
print(f"  │         Safe        Phishing          │")
print(f"  │ Actual  Safe   TN={tn:5d}    FP={fp:5d} │")
print(f"  │ Actual  Phish  FN={fn:5d}    TP={tp:5d} │")
print(f"  └─────────────────────────────────────┘")

print(f"\n  Key Metrics:")
print(f"    Accuracy:           {best['accuracy']:.4f}  ({best['accuracy']*100:.2f}%)")
print(f"    Precision:          {best['precision']:.4f}  (of flagged, how many are real phishing)")
print(f"    Recall:             {best['recall']:.4f}  (of real phishing, how many caught)")
print(f"    F1 Score:           {best['f1']:.4f}  (balance of precision + recall)")
print(f"    ROC-AUC:            {best['roc_auc']:.4f}  (1.0 = perfect, 0.5 = random)")
print(f"    False Positive Rate:{fpr:.4f}  (safe emails wrongly flagged)")
print(f"    False Negative Rate:{fnr:.4f}  (phishing emails missed)")

print(f"\n  Full Classification Report:")
print(classification_report(y_test, y_pred, target_names=["Safe/Ham", "Phishing/Spam"]))

# Cross-validation for robustness check
print(f"  Cross-Validation (5-fold F1 scores):")
cv_scores = cross_val_score(
    trained_models[best_name], X_vec, y,
    cv=5, scoring="f1", n_jobs=-1
)
print(f"    Scores: {[f'{s:.3f}' for s in cv_scores]}")
print(f"    Mean:   {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
print(f"    Stable model: {'✓ Yes' if cv_scores.std() < 0.05 else '⚠ High variance'}")


# ─────────────────────────────────────────────
#  STEP 8: THRESHOLD ANALYSIS
# ─────────────────────────────────────────────

section("STEP 8: Probability Threshold Analysis")

print(f"  Effect of different classification thresholds:")
print(f"  (Current threshold: 0.5 — predictions above this = phishing)")
print()
print(f"  {'Threshold':>10} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Flagged':>10}")
print(f"  {'─'*10} {'─'*10} {'─'*10} {'─'*10} {'─'*10}")

for thresh in [0.3, 0.4, 0.5, 0.6, 0.7, 0.8]:
    preds = (y_prob >= thresh).astype(int)
    prec  = precision_score(y_test, preds, zero_division=0)
    rec   = recall_score(y_test, preds, zero_division=0)
    f1    = f1_score(y_test, preds, zero_division=0)
    flagged = preds.sum()
    marker  = " ← current" if thresh == 0.5 else ""
    print(f"  {thresh:>10.1f} {prec:>10.3f} {rec:>10.3f} {f1:>10.3f} {flagged:>10}{marker}")

print()
print("  Interpretation:")
print("  ─ Lower threshold = catches more phishing (higher recall)")
print("    but also flags more safe emails (lower precision)")
print("  ─ Higher threshold = fewer false positives")
print("    but misses more phishing emails")
print("  ─ For a security system, higher recall is preferred")
print("    Missing phishing is worse than a false alarm")


# ─────────────────────────────────────────────
#  STEP 9: SAVE MODEL AND REPORT
# ─────────────────────────────────────────────

section("STEP 9: Saving Model and Report")

# Save best model
model_path = os.path.join(MODEL_DIR, "email_model.pkl")
vect_path  = os.path.join(MODEL_DIR, "vectorizer.pkl")

with open(model_path, "wb") as f:
    pickle.dump(trained_models[best_name], f)

with open(vect_path, "wb") as f:
    pickle.dump(vectorizer, f)

print(f"  ✓ Model saved:      {model_path}")
print(f"  ✓ Vectorizer saved: {vect_path}")

# Save evaluation report (for your project documentation)
report_lines = [
    "BrowserShield — ML Model Evaluation Report",
    "=" * 50,
    "",
    f"Dataset:         SpamAssassin",
    f"Total Samples:   {after:,}",
    f"Phishing:        {phishing_count:,} ({phishing_count/after*100:.1f}%)",
    f"Safe:            {safe_count:,}  ({safe_count/after*100:.1f}%)",
    f"Features:        TF-IDF, {len(vectorizer.vocabulary_):,} terms, unigrams+bigrams",
    "",
    "Model Comparison:",
    "-" * 50,
    f"{'Model':<25} {'Accuracy':>10} {'F1':>10} {'ROC-AUC':>10}",
]

for name, r in results.items():
    marker = " ← SELECTED" if name == best_name else ""
    report_lines.append(
        f"{name:<25} {r['accuracy']:>10.4f} {r['f1']:>10.4f} {r['roc_auc']:>10.4f}{marker}"
    )

report_lines += [
    "",
    f"Best Model: {best_name}",
    "",
    "Detailed Metrics (Best Model):",
    "-" * 50,
    f"Accuracy:            {best['accuracy']:.4f}",
    f"Precision:           {best['precision']:.4f}",
    f"Recall:              {best['recall']:.4f}",
    f"F1 Score:            {best['f1']:.4f}",
    f"ROC-AUC:             {best['roc_auc']:.4f}",
    f"False Positive Rate: {fpr:.4f}",
    f"False Negative Rate: {fnr:.4f}",
    "",
    "Confusion Matrix:",
    f"  True Negatives  (safe, correctly passed):   {tn}",
    f"  False Positives (safe, wrongly flagged):     {fp}",
    f"  False Negatives (phishing, missed):          {fn}",
    f"  True Positives  (phishing, correctly caught):{tp}",
    "",
    f"Cross-Validation (5-fold F1): {cv_scores.mean():.4f} ± {cv_scores.std():.4f}",
]

with open(REPORT_PATH, "w", encoding="utf-8") as f:
    f.write("\n".join(report_lines))


print(f"  ✓ Evaluation report: {REPORT_PATH}")

# ─────────────────────────────────────────────
#  FINAL SUMMARY
# ─────────────────────────────────────────────

section("TRAINING COMPLETE")

print(f"  Best Model:    {best_name}")
print(f"  Accuracy:      {best['accuracy']*100:.2f}%")
print(f"  F1 Score:      {best['f1']:.4f}")
print(f"  ROC-AUC:       {best['roc_auc']:.4f}")
print(f"  FP Rate:       {fpr*100:.2f}% (safe emails wrongly flagged)")
print(f"  FN Rate:       {fnr*100:.2f}% (phishing emails missed)")
print()
print("  Files saved:")
print(f"    {model_path}")
print(f"    {vect_path}")
print(f"    {REPORT_PATH}")
separator()