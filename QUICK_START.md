# PhishGuard AI - Quick Reference Guide

## 🚀 Installation (5 minutes)

```bash
# 1. Navigate to project
cd d:\CyberProjects\PhishGuard-AI

# 2. Create virtual environment (if not exists)
python -m venv venv

# 3. Activate virtual environment
venv\Scripts\activate  # Windows

# 4. Install dependencies
pip install -r requirements.txt

# 5. Verify installation
python -c "import xgboost, lightgbm, shap; print('✓ Ready!')"
```

---

## 📊 Complete Research Pipeline

### Step 1: Test Feature Extraction (30 seconds)
```bash
python src\advanced_features.py
```

**Expected Output:**
```
======================================================================
PHISHGUARD ADVANCED FEATURE EXTRACTION - TEST MODE
======================================================================

Testing feature extraction on 8 sample URLs...

[1] URL: https://www.google.com
----------------------------------------------------------------------
  url_length                : 23.000
  domain_entropy            : 2.321
  homograph_score           : 0.000
  bitsquat_suspicion        : 0
  tld_risk_score            : 0.000
  ...

✓ Feature extraction test complete!
  Total features: 38
```

---

### Step 2: Train Advanced Model (45 minutes)
```bash
python src\train_advanced_model.py
```

**What Happens:**
1. Loads 651K URLs from `malicious_phish_cleaned.csv`
2. Extracts 38 features (5-10 minutes)
3. Applies SMOTE balancing
4. Optimizes XGBoost hyperparameters (50 trials, ~15 min)
5. Optimizes LightGBM hyperparameters (50 trials, ~15 min)
6. Trains Random Forest baseline
7. Trains stacking ensemble
8. Evaluates all models on test set
9. Saves models to `models/` directory

**Expected Output:**
```
======================================================================
PHISHGUARD AI - ADVANCED MODEL TRAINING PIPELINE
======================================================================

STEP 1: DATA LOADING & FEATURE EXTRACTION
[1/4] Loading dataset...
  ✓ Loaded 651,191 URLs

[2/4] Extracting advanced features (38 features)...
  Processed 0/651,191 URLs (0.0%)
  Processed 10,000/651,191 URLs (1.5%)
  ...
  ✓ Completed: 651,191/651,191 URLs (100.0%)

STEP 2: DATA SPLITTING & BALANCING
[1/3] Splitting data (test=20%)...
  ✓ Training set:   417,562 samples
  ✓ Validation set:  65,391 samples
  ✓ Test set:       130,238 samples

[2/3] Applying SMOTE to training set...
  ✓ Training set after SMOTE: 1,712,412 samples

STEP 3A: XGBOOST HYPERPARAMETER OPTIMIZATION
Running Optuna optimization (50 trials)...
[I 2026-02-17 10:00:00] Trial 0: 0.9234
[I 2026-02-17 10:02:15] Trial 1: 0.9312
...
✓ Optimization complete!
  Best F1-score: 0.9672

STEP 4: MODEL TRAINING
[1/4] Training XGBoost...
  ✓ XGBoost training complete

[2/4] Training LightGBM...
  ✓ LightGBM training complete

[3/4] Training Random Forest (baseline)...
  ✓ Random Forest training complete

[4/4] Training Stacking Ensemble...
  ✓ Stacking Ensemble training complete

STEP 5: MODEL EVALUATION
======================================================================
Evaluating: XGBOOST
======================================================================

Accuracy:          0.9783
F1-Score (macro):  0.9672
Precision (macro): 0.9624
Recall (macro):    0.9714
MCC:               0.9621
ROC-AUC (macro):   0.9942

TRAINING COMPLETE!
======================================================================
Model Performance Summary (F1-Score Macro):
  xgboost              : 0.9672
  lightgbm             : 0.9658
  random_forest        : 0.9341
  stacking             : 0.9689

🏆 Best Model: STACKING (F1=0.9689)
```

**Outputs:**
- `models/xgboost_model.pkl` (12 MB)
- `models/lightgbm_model.pkl` (10 MB)
- `models/random_forest_model.pkl` (8 MB)
- `models/stacking_model.pkl` (15 MB)
- `models/feature_names_advanced.pkl`
- `models/label_encoder.pkl`
- `results/performance_metrics/model_comparison.json`

---

### Step 3: Generate SHAP Visualizations (10 minutes)
```bash
python src\explainability_analysis.py
```

**What Happens:**
1. Loads trained XGBoost model
2. Samples 1,000 URLs for SHAP analysis
3. Computes SHAP values (TreeExplainer)
4. Generates 10+ publication-quality plots

**Expected Output:**
```
======================================================================
PHISHGUARD AI - SHAP EXPLAINABILITY ANALYSIS
======================================================================

LOADING MODEL & DATA
[1/4] Loading model from ../models/xgboost_model.pkl...
  ✓ Model loaded

[2/4] Loading metadata...
  ✓ Features: 38
  ✓ Classes: ['benign', 'defacement', 'malware', 'phishing']

[3/4] Loading dataset...
  ⚠ Sampling 1,000 URLs for SHAP analysis...
  ✓ Loaded 1,000 URLs

[4/4] Extracting features...
  ✓ Feature matrix: (1000, 38)

GENERATING SHAP EXPLANATIONS
[1/2] Creating SHAP explainer...
  ✓ Explainer created

[2/2] Computing SHAP values...
  ✓ SHAP values computed

PLOT 1: SHAP SUMMARY (BEESWARM)
  Generating summary plot for class: benign
    ✓ Saved to ../results/shap_plots/shap_summary_benign.png
  Generating summary plot for class: phishing
    ✓ Saved to ../results/shap_plots/shap_summary_phishing.png
  ...

PLOT 2: SHAP FEATURE IMPORTANCE
  ✓ Saved to ../results/shap_plots/shap_feature_importance.png

  Top 10 Most Important Features:
    domain_entropy                : 0.1247
    suspicious_words              : 0.0982
    url_length                    : 0.0876
    tld_risk_score                : 0.0734
    ...

SHAP ANALYSIS COMPLETE!
```

**Outputs:**
- `results/shap_plots/shap_summary_*.png` (4 files)
- `results/shap_plots/shap_feature_importance.png`
- `results/shap_plots/feature_importance_table.csv`
- `results/shap_plots/dependence_plots/` (5 files)
- `results/shap_plots/waterfall_plots/` (12 files)

---

### Step 4: Run Stress Tests (15 minutes)
```bash
python src\stress_test.py
```

**What Happens:**
1. Temporal evaluation (time-series split)
2. Adversarial robustness testing (3 attack types)
3. Comparison with baseline model
4. Generates comparison visualizations

**Expected Output:**
```
======================================================================
PHISHGUARD AI - STRESS TESTING & TEMPORAL EVALUATION
======================================================================

TEST 1: TEMPORAL EVALUATION (TIME-SERIES SPLIT)
[1/4] Creating temporal split...
  Temporal split:
    Training (old):   455,633 samples (70%)
    Validation:       97,778 samples (15%)
    Test (new/2026):  97,780 samples (15%)

[2/4] Evaluating ADVANCED model on temporal test set...
  Advanced Model Performance:
    Accuracy:  0.9362
    F1-Score:  0.9187
    Precision: 0.9124
    Recall:    0.9251

[3/4] Evaluating BASELINE model on temporal test set...
  Baseline Model Performance:
    Accuracy:  0.8934
    F1-Score:  0.8721

  Improvement (Advanced vs Baseline):
    Accuracy:  +4.28%
    F1-Score:  +4.66%

TEST 2: ADVERSARIAL ROBUSTNESS
[Attack 1/3] Homograph Substitution
    Accuracy under attack: 0.8912
    F1-Score under attack: 0.8734

[Attack 2/3] URL Padding/Obfuscation
    Accuracy under attack: 0.8876
    F1-Score under attack: 0.8698

[Attack 3/3] Subdomain Manipulation
    Accuracy under attack: 0.9021
    F1-Score under attack: 0.8845

  Adversarial Robustness Summary:
    Overall Robustness Score: 87.5%

STRESS TESTING COMPLETE!
```

**Outputs:**
- `results/stress_tests/temporal_comparison.png`
- `results/stress_tests/adversarial_robustness.png`
- `results/stress_tests/stress_test_results.json`

---

### Step 5: Generate Architecture Diagram (5 seconds)
```bash
python src\generate_architecture_diagram.py
```

**Expected Output:**
```
✓ System architecture diagram saved to: ../docs/system_architecture.png

======================================================================
ARCHITECTURE DIAGRAM GENERATION COMPLETE!
======================================================================

Output: ../docs/system_architecture.png
Resolution: 4800x3600 pixels (300 DPI)
Format: PNG
```

**Output:**
- `docs/system_architecture.png` (high-resolution diagram)

---

## 🌐 Run Web Application

```bash
python app.py
```

**Expected Output:**
```
✓ ML model loaded successfully!
 * Serving Flask app 'app'
 * Debug mode: off
WARNING: This is a development server. Do not use it in production.
 * Running on http://0.0.0.0:5000
Press CTRL+C to quit
```

**Access:** http://localhost:5000

---

## 📊 View Results

### SHAP Plots
```bash
# Open in default image viewer
start results\shap_plots\shap_feature_importance.png
start results\shap_plots\shap_summary_phishing.png
```

### Stress Test Results
```bash
# Open visualizations
start results\stress_tests\temporal_comparison.png
start results\stress_tests\adversarial_robustness.png

# View JSON results
type results\stress_tests\stress_test_results.json
```

### Model Performance
```bash
# View model comparison
type results\performance_metrics\model_comparison.json
```

---

## 🐛 Troubleshooting

### Issue: "Module not found"
```bash
# Solution: Reinstall dependencies
pip install -r requirements.txt --upgrade
```

### Issue: "Out of memory"
```bash
# Solution: Reduce dataset size in CONFIG
# Edit src/train_advanced_model.py:
CONFIG = {
    'max_samples': 100000,  # Limit to 100K URLs
    ...
}
```

### Issue: "SHAP takes too long"
```bash
# Solution: Reduce SHAP sample size
# Edit src/explainability_analysis.py:
CONFIG = {
    'max_samples_shap': 500,  # Reduce from 1000
    ...
}
```

### Issue: "Optuna optimization slow"
```bash
# Solution: Reduce trials
# Edit src/train_advanced_model.py:
CONFIG = {
    'n_optuna_trials': 20,  # Reduce from 50
    ...
}
```

---

## 📁 File Locations

### Input Data
- `malicious_phish.csv` (original dataset, 45 MB)
- `malicious_phish_cleaned.csv` (cleaned dataset, 43 MB)

### Trained Models
- `models/xgboost_model.pkl`
- `models/lightgbm_model.pkl`
- `models/random_forest_model.pkl`
- `models/stacking_model.pkl`

### Results
- `results/shap_plots/` (SHAP visualizations)
- `results/performance_metrics/` (model comparison)
- `results/stress_tests/` (robustness tests)

### Documentation
- `docs/technical_walkthrough.md` (60+ page research paper)
- `docs/system_architecture.png` (architecture diagram)
- `README.md` (project overview)

---

## ⏱️ Time Estimates

| Task | Time (CPU) | Time (GPU) |
|------|-----------|-----------|
| Feature extraction test | 30 sec | 30 sec |
| Full model training | 45 min | 15 min |
| SHAP analysis | 10 min | 5 min |
| Stress tests | 15 min | 8 min |
| Architecture diagram | 5 sec | 5 sec |
| **Total** | **~70 min** | **~30 min** |

---

## 🎯 Quick Commands Cheat Sheet

```bash
# Test everything is working
python src\advanced_features.py

# Train models (long-running)
python src\train_advanced_model.py

# Generate all visualizations
python src\explainability_analysis.py
python src\stress_test.py
python src\generate_architecture_diagram.py

# Run web app
python app.py

# View results
start results\shap_plots\shap_feature_importance.png
start docs\technical_walkthrough.md
```

---

## 📞 Support

- **Documentation:** `docs/technical_walkthrough.md`
- **Code Comments:** All functions have detailed docstrings
- **Issues:** Check error messages in terminal
- **Email:** phishguard-research@example.com

---

**Last Updated:** February 17, 2026  
**Version:** 2.0.0
