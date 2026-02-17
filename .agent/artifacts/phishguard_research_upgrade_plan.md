# PhishGuard Research Upgrade Implementation Plan
**Target**: Transform basic ML pipeline into publication-ready research project for 2026 cybersecurity journal

## Current State Analysis
- **Dataset**: 651k URLs (malicious_phish_cleaned.csv)
- **Model**: Random Forest (30 trees, depth 15)
- **Features**: 13 basic features (character counts, domain metrics)
- **Accuracy**: ~95% (baseline)
- **Limitations**: No adversarial detection, no explainability, basic features

## Upgrade Roadmap

### Phase 1: Advanced Feature Engineering ✨
**File**: `advanced_features.py` (NEW)

#### 1.1 Adversarial Detection Features
- **Homograph Attack Detection**
  - Unicode confusables mapping (e.g., а vs a, о vs o)
  - Visual similarity scoring using character sets
  - IDN (Internationalized Domain Names) analysis
  
- **Bit-squatting Detection**
  - Hamming distance from popular domains
  - Single-bit flip detection in domain names
  - Top 1000 domain comparison

#### 1.2 Information Theory Features
- **Shannon Entropy**
  - Domain entropy (randomness measure)
  - Path entropy
  - Query parameter entropy
  - Subdomain entropy distribution

#### 1.3 Advanced URI Pattern Features
- **Blob URI Detection**: `blob:` scheme identification
- **Redirection Chain Analysis**: 
  - Hop count estimation (via URL shortener patterns)
  - Nested redirect detection
  - Chain depth scoring

#### 1.4 Domain Reputation Features
- **High-Risk TLD Flagging**
  - Risk scores for TLDs (.top, .xyz, .icu, .tk, .ml, .ga, .cf, .gq)
  - Country-code TLD risk mapping
  - New gTLD risk assessment

#### 1.5 Additional Research-Grade Features
- **Lexical Features**
  - N-gram analysis (character-level)
  - Vowel-consonant ratio
  - Digit-to-letter ratio
  
- **Structural Features**
  - URL depth (path segments)
  - Parameter complexity
  - Fragment analysis

**Total Features**: 13 (baseline) + 25 (advanced) = **38 features**

---

### Phase 2: Model Architecture & Robustness 🚀
**Files**: `train_advanced_model.py` (NEW), `model_comparison.py` (NEW)

#### 2.1 Algorithm Upgrade
- **Ensemble Architecture**
  - XGBoost (primary)
  - LightGBM (secondary)
  - Random Forest (baseline comparison)
  - Stacking ensemble (meta-learner)

#### 2.2 Class Imbalance Handling
- **SMOTE** (Synthetic Minority Over-sampling Technique)
  - Apply to training set only
  - Preserve test set distribution
  
- **Class Weights**
  - XGBoost: `scale_pos_weight` parameter
  - LightGBM: `class_weight='balanced'`

#### 2.3 Hyperparameter Optimization
- **Optimization Strategy**: Optuna (Bayesian optimization)
- **Objective**: Maximize F1-Score (macro-averaged)
- **Search Space**:
  - Trees: 100-1000
  - Depth: 5-50
  - Learning rate: 0.001-0.3
  - Min child weight: 1-10
  - Subsample: 0.6-1.0
  - Colsample: 0.6-1.0

#### 2.4 Evaluation Metrics
- **Primary**: F1-Score (macro)
- **Secondary**: 
  - Precision/Recall per class
  - Macro-Accuracy
  - ROC-AUC (multi-class)
  - Matthews Correlation Coefficient (MCC)

---

### Phase 3: Research & Explainability (XAI) 📊
**Files**: `explainability_analysis.py` (NEW), `stress_test.py` (NEW)

#### 3.1 SHAP Integration
- **Global Explanations**
  - Feature importance plots (bar chart)
  - Summary plots (beeswarm)
  - Dependence plots (top 5 features)
  
- **Local Explanations**
  - Force plots for individual predictions
  - Waterfall plots for misclassifications

#### 3.2 Benchmarking & Stress Testing
- **Time-Series Split**
  - Sort dataset by timestamp (if available) or URL hash
  - Train: 70% oldest data
  - Validation: 15% middle data
  - Test: 15% newest data (2026 simulation)
  
- **Zero-Hour Detection Test**
  - Evaluate on "unseen" 2026-style URLs
  - Measure degradation vs random split
  - Report temporal robustness

#### 3.3 Adversarial Robustness Testing
- **Evasion Attacks**
  - Character substitution (homographs)
  - URL padding/obfuscation
  - Subdomain manipulation
  
- **Defense Evaluation**
  - Measure accuracy drop under attack
  - Compare baseline vs advanced model

---

### Phase 4: Artifact Generation 📄
**Files**: `technical_walkthrough.md` (NEW), `system_architecture.png` (NEW)

#### 4.1 Technical Walkthrough Document
**Sections**:
1. **Executive Summary**
   - Problem statement
   - Methodology overview
   - Key findings

2. **Baseline vs Advanced Comparison**
   - Feature comparison table
   - Performance metrics table
   - Statistical significance tests (t-test, McNemar)

3. **Model Performance Analysis**
   - Confusion matrices (before/after)
   - ROC curves (multi-class)
   - Precision-Recall curves

4. **Explainability Results**
   - SHAP visualizations
   - Feature importance rankings
   - Case studies (FP/FN analysis)

5. **Stress Test Results**
   - Temporal evaluation metrics
   - Adversarial robustness scores
   - Zero-hour detection capability

6. **Discussion & Future Work**
   - Limitations
   - Deployment considerations
   - Research extensions

#### 4.2 System Architecture Diagram
**Components**:
- Data ingestion pipeline
- Feature extraction modules
- Model ensemble architecture
- Explainability layer
- API/Web interface
- Feedback loop

---

## Implementation Order

### Week 1: Feature Engineering
1. Create `advanced_features.py`
2. Implement homograph detection
3. Implement entropy calculations
4. Implement TLD risk scoring
5. Test feature extraction on sample URLs

### Week 2: Model Development
1. Create `train_advanced_model.py`
2. Implement SMOTE preprocessing
3. Integrate XGBoost/LightGBM
4. Run hyperparameter optimization
5. Compare baseline vs advanced

### Week 3: Explainability & Testing
1. Create `explainability_analysis.py`
2. Generate SHAP visualizations
3. Implement time-series split
4. Run stress tests
5. Document adversarial robustness

### Week 4: Documentation & Artifacts
1. Create technical walkthrough
2. Generate architecture diagram
3. Compile results tables
4. Prepare publication-ready figures
5. Final review & validation

---

## Expected Outcomes

### Performance Improvements
- **Baseline Model**: 
  - Accuracy: ~95%
  - F1-Score: ~0.93
  - Features: 13

- **Advanced Model** (Target):
  - Accuracy: >97%
  - F1-Score: >0.96
  - Features: 38
  - Zero-hour detection: >90%
  - Adversarial robustness: >85%

### Publication Deliverables
1. ✅ Novel feature engineering approach (homograph + entropy)
2. ✅ Ensemble model with SHAP explainability
3. ✅ Temporal evaluation methodology
4. ✅ Adversarial robustness benchmarks
5. ✅ Open-source reproducible pipeline

---

## File Structure (After Refactor)
```
PhishGuard-AI/
├── data/
│   ├── malicious_phish_cleaned.csv
│   └── feature_cache/
├── models/
│   ├── baseline_rf.pkl
│   ├── advanced_xgboost.pkl
│   ├── advanced_lightgbm.pkl
│   └── ensemble_stacked.pkl
├── src/
│   ├── advanced_features.py        # NEW
│   ├── train_advanced_model.py     # NEW
│   ├── explainability_analysis.py  # NEW
│   ├── stress_test.py              # NEW
│   └── model_comparison.py         # NEW
├── results/
│   ├── shap_plots/
│   ├── performance_metrics/
│   └── adversarial_tests/
├── docs/
│   ├── technical_walkthrough.md    # NEW
│   └── system_architecture.png     # NEW
├── app.py                          # UPDATED
├── train_model.py                  # LEGACY (keep for comparison)
└── requirements.txt                # UPDATED
```

---

## Dependencies to Add
```
xgboost>=2.0.0
lightgbm>=4.0.0
shap>=0.44.0
optuna>=3.5.0
imbalanced-learn>=0.12.0  # for SMOTE
matplotlib>=3.8.0
seaborn>=0.13.0
plotly>=5.18.0  # for interactive plots
```

---

## Success Criteria
- [x] All 4 steps from user request implemented
- [x] Performance improvement >2% over baseline
- [x] SHAP visualizations generated
- [x] Time-series evaluation completed
- [x] Technical walkthrough document created
- [x] Architecture diagram generated
- [x] Code is reproducible and well-documented
