"""
PhishGuard AI - Advanced Model Training Pipeline
=================================================
Research-grade model training with:
- XGBoost & LightGBM ensemble
- SMOTE for class imbalance
- Hyperparameter optimization (Optuna)
- Comprehensive evaluation metrics

Author: PhishGuard Research Team
Date: 2026-02-17
Version: 2.0.0 (Research Edition)
"""

import pandas as pd
import numpy as np
import sys
import os
from pathlib import Path
import joblib
import json
from datetime import datetime

# ML libraries
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import (
    classification_report, accuracy_score, confusion_matrix,
    f1_score, precision_score, recall_score, roc_auc_score,
    matthews_corrcoef
)
from sklearn.preprocessing import LabelEncoder
from imblearn.over_sampling import SMOTE

# Ensemble models
import xgboost as xgb
import lightgbm as lgb
from sklearn.ensemble import RandomForestClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression

# Hyperparameter optimization
import optuna
from optuna.samplers import TPESampler

# Add src directory to path
sys.path.append(str(Path(__file__).parent))
from advanced_features import extract_features_batch, get_feature_names


# ============================================================================
# CONFIGURATION
# ============================================================================

CONFIG = {
    'data_path': '../malicious_phish_cleaned.csv',
    'output_dir': '../models',
    'results_dir': '../results/performance_metrics',
    'test_size': 0.2,
    'val_size': 0.1,  # From training set
    'random_state': 42,
    'n_optuna_trials': 50,  # Hyperparameter optimization trials
    'cv_folds': 5,
    'use_smote': True,
    'smote_sampling_strategy': 'auto',  # Balance all minority classes
    'max_samples': None,  # Set to integer to limit dataset size for testing
}


# ============================================================================
# DATA LOADING & PREPROCESSING
# ============================================================================

def load_and_prepare_data(config):
    """
    Load dataset and extract advanced features.
    
    Args:
        config (dict): Configuration dictionary
        
    Returns:
        tuple: (X, y, feature_names, label_encoder)
    """
    print("=" * 70)
    print("STEP 1: DATA LOADING & FEATURE EXTRACTION")
    print("=" * 70)
    
    # Load dataset
    print(f"\n[1/4] Loading dataset from {config['data_path']}...")
    df = pd.read_csv(config['data_path'])
    
    # Limit samples if specified (for testing)
    if config['max_samples'] is not None:
        print(f"  ⚠ Limiting to {config['max_samples']:,} samples for testing...")
        df = df.sample(n=min(config['max_samples'], len(df)), random_state=config['random_state'])
    
    print(f"  ✓ Loaded {len(df):,} URLs")
    print(f"  Class distribution:\n{df['type'].value_counts()}\n")
    
    # Extract advanced features
    print("[2/4] Extracting advanced features (38 features)...")
    print("  This may take several minutes for large datasets...")
    
    features_list = extract_features_batch(df['url'].tolist(), verbose=True)
    
    # Convert to DataFrame
    print("\n[3/4] Creating feature matrix...")
    X = pd.DataFrame(features_list)
    y = df['type']
    
    print(f"  ✓ Feature matrix shape: {X.shape}")
    print(f"  ✓ Features: {len(X.columns)}")
    
    # Encode labels
    print("\n[4/4] Encoding class labels...")
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    
    print(f"  ✓ Classes: {list(label_encoder.classes_)}")
    print(f"  ✓ Encoded as: {list(range(len(label_encoder.classes_)))}")
    
    return X, y_encoded, list(X.columns), label_encoder


# ============================================================================
# TRAIN/VAL/TEST SPLIT WITH SMOTE
# ============================================================================

def split_and_balance_data(X, y, config):
    """
    Split data and apply SMOTE to training set.
    
    Args:
        X (pd.DataFrame): Feature matrix
        y (np.array): Encoded labels
        config (dict): Configuration dictionary
        
    Returns:
        tuple: (X_train, X_val, X_test, y_train, y_val, y_test)
    """
    print("\n" + "=" * 70)
    print("STEP 2: DATA SPLITTING & BALANCING")
    print("=" * 70)
    
    # First split: train+val vs test
    print(f"\n[1/3] Splitting data (test={config['test_size']*100:.0f}%)...")
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y,
        test_size=config['test_size'],
        random_state=config['random_state'],
        stratify=y
    )
    
    # Second split: train vs val
    val_size_adjusted = config['val_size'] / (1 - config['test_size'])
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp,
        test_size=val_size_adjusted,
        random_state=config['random_state'],
        stratify=y_temp
    )
    
    print(f"  ✓ Training set:   {len(X_train):,} samples")
    print(f"  ✓ Validation set: {len(X_val):,} samples")
    print(f"  ✓ Test set:       {len(X_test):,} samples")
    
    # Apply SMOTE to training set only
    if config['use_smote']:
        print(f"\n[2/3] Applying SMOTE to training set...")
        print(f"  Original class distribution:")
        unique, counts = np.unique(y_train, return_counts=True)
        for cls, count in zip(unique, counts):
            print(f"    Class {cls}: {count:,} samples")
        
        smote = SMOTE(
            sampling_strategy=config['smote_sampling_strategy'],
            random_state=config['random_state'],
            k_neighbors=5
        )
        
        X_train_balanced, y_train_balanced = smote.fit_resample(X_train, y_train)
        
        print(f"\n  Balanced class distribution:")
        unique, counts = np.unique(y_train_balanced, return_counts=True)
        for cls, count in zip(unique, counts):
            print(f"    Class {cls}: {count:,} samples")
        
        print(f"\n  ✓ Training set after SMOTE: {len(X_train_balanced):,} samples")
        
        X_train = X_train_balanced
        y_train = y_train_balanced
    else:
        print(f"\n[2/3] Skipping SMOTE (disabled in config)")
    
    print(f"\n[3/3] Final dataset sizes:")
    print(f"  Training:   {len(X_train):,}")
    print(f"  Validation: {len(X_val):,}")
    print(f"  Test:       {len(X_test):,}")
    
    return X_train, X_val, X_test, y_train, y_val, y_test


# ============================================================================
# HYPERPARAMETER OPTIMIZATION WITH OPTUNA
# ============================================================================

def optimize_xgboost(X_train, y_train, X_val, y_val, n_trials=50):
    """
    Optimize XGBoost hyperparameters using Optuna.
    
    Args:
        X_train, y_train: Training data
        X_val, y_val: Validation data
        n_trials (int): Number of optimization trials
        
    Returns:
        dict: Best hyperparameters
    """
    print("\n" + "=" * 70)
    print("STEP 3A: XGBOOST HYPERPARAMETER OPTIMIZATION")
    print("=" * 70)
    
    def objective(trial):
        """Optuna objective function."""
        params = {
            'objective': 'multi:softmax',
            'num_class': len(np.unique(y_train)),
            'eval_metric': 'mlogloss',
            'tree_method': 'hist',
            'random_state': CONFIG['random_state'],
            
            # Hyperparameters to optimize
            'n_estimators': trial.suggest_int('n_estimators', 100, 1000, step=100),
            'max_depth': trial.suggest_int('max_depth', 5, 50),
            'learning_rate': trial.suggest_float('learning_rate', 0.001, 0.3, log=True),
            'min_child_weight': trial.suggest_int('min_child_weight', 1, 10),
            'subsample': trial.suggest_float('subsample', 0.6, 1.0),
            'colsample_bytree': trial.suggest_float('colsample_bytree', 0.6, 1.0),
            'gamma': trial.suggest_float('gamma', 0, 5),
            'reg_alpha': trial.suggest_float('reg_alpha', 0, 10),
            'reg_lambda': trial.suggest_float('reg_lambda', 0, 10),
        }
        
        # Train model
        model = xgb.XGBClassifier(**params, verbosity=0)
        model.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=False)
        
        # Evaluate on validation set
        y_pred = model.predict(X_val)
        f1 = f1_score(y_val, y_pred, average='macro')
        
        return f1
    
    # Run optimization
    print(f"\nRunning Optuna optimization ({n_trials} trials)...")
    print("  Objective: Maximize macro F1-score")
    print("  This may take 10-30 minutes...\n")
    
    study = optuna.create_study(
        direction='maximize',
        sampler=TPESampler(seed=CONFIG['random_state'])
    )
    
    study.optimize(objective, n_trials=n_trials, show_progress_bar=True)
    
    print(f"\n✓ Optimization complete!")
    print(f"  Best F1-score: {study.best_value:.4f}")
    print(f"  Best parameters:")
    for param, value in study.best_params.items():
        print(f"    {param}: {value}")
    
    return study.best_params


def optimize_lightgbm(X_train, y_train, X_val, y_val, n_trials=50):
    """
    Optimize LightGBM hyperparameters using Optuna.
    
    Args:
        X_train, y_train: Training data
        X_val, y_val: Validation data
        n_trials (int): Number of optimization trials
        
    Returns:
        dict: Best hyperparameters
    """
    print("\n" + "=" * 70)
    print("STEP 3B: LIGHTGBM HYPERPARAMETER OPTIMIZATION")
    print("=" * 70)
    
    def objective(trial):
        """Optuna objective function."""
        params = {
            'objective': 'multiclass',
            'num_class': len(np.unique(y_train)),
            'metric': 'multi_logloss',
            'verbosity': -1,
            'random_state': CONFIG['random_state'],
            
            # Hyperparameters to optimize
            'n_estimators': trial.suggest_int('n_estimators', 100, 1000, step=100),
            'max_depth': trial.suggest_int('max_depth', 5, 50),
            'learning_rate': trial.suggest_float('learning_rate', 0.001, 0.3, log=True),
            'num_leaves': trial.suggest_int('num_leaves', 20, 300),
            'min_child_samples': trial.suggest_int('min_child_samples', 5, 100),
            'subsample': trial.suggest_float('subsample', 0.6, 1.0),
            'colsample_bytree': trial.suggest_float('colsample_bytree', 0.6, 1.0),
            'reg_alpha': trial.suggest_float('reg_alpha', 0, 10),
            'reg_lambda': trial.suggest_float('reg_lambda', 0, 10),
        }
        
        # Train model
        model = lgb.LGBMClassifier(**params)
        model.fit(X_train, y_train, eval_set=[(X_val, y_val)], callbacks=[lgb.early_stopping(50, verbose=False)])
        
        # Evaluate on validation set
        y_pred = model.predict(X_val)
        f1 = f1_score(y_val, y_pred, average='macro')
        
        return f1
    
    # Run optimization
    print(f"\nRunning Optuna optimization ({n_trials} trials)...")
    print("  Objective: Maximize macro F1-score")
    print("  This may take 10-30 minutes...\n")
    
    study = optuna.create_study(
        direction='maximize',
        sampler=TPESampler(seed=CONFIG['random_state'])
    )
    
    study.optimize(objective, n_trials=n_trials, show_progress_bar=True)
    
    print(f"\n✓ Optimization complete!")
    print(f"  Best F1-score: {study.best_value:.4f}")
    print(f"  Best parameters:")
    for param, value in study.best_params.items():
        print(f"    {param}: {value}")
    
    return study.best_params


# ============================================================================
# MODEL TRAINING
# ============================================================================

def train_ensemble_models(X_train, y_train, X_val, y_val, config):
    """
    Train ensemble of XGBoost, LightGBM, and Random Forest.
    
    Args:
        X_train, y_train: Training data
        X_val, y_val: Validation data
        config (dict): Configuration dictionary
        
    Returns:
        dict: Trained models
    """
    print("\n" + "=" * 70)
    print("STEP 4: MODEL TRAINING")
    print("=" * 70)
    
    models = {}
    
    # ========================================================================
    # 1. XGBoost (Optimized)
    # ========================================================================
    print("\n[1/4] Training XGBoost...")
    
    # Optimize hyperparameters
    best_xgb_params = optimize_xgboost(X_train, y_train, X_val, y_val, n_trials=config['n_optuna_trials'])
    
    # Train final model
    xgb_params = {
        'objective': 'multi:softmax',
        'num_class': len(np.unique(y_train)),
        'eval_metric': 'mlogloss',
        'tree_method': 'hist',
        'random_state': config['random_state'],
        **best_xgb_params
    }
    
    models['xgboost'] = xgb.XGBClassifier(**xgb_params, verbosity=1)
    models['xgboost'].fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=True)
    
    print("  ✓ XGBoost training complete")
    
    # ========================================================================
    # 2. LightGBM (Optimized)
    # ========================================================================
    print("\n[2/4] Training LightGBM...")
    
    # Optimize hyperparameters
    best_lgb_params = optimize_lightgbm(X_train, y_train, X_val, y_val, n_trials=config['n_optuna_trials'])
    
    # Train final model
    lgb_params = {
        'objective': 'multiclass',
        'num_class': len(np.unique(y_train)),
        'metric': 'multi_logloss',
        'verbosity': -1,
        'random_state': config['random_state'],
        **best_lgb_params
    }
    
    models['lightgbm'] = lgb.LGBMClassifier(**lgb_params)
    models['lightgbm'].fit(X_train, y_train, eval_set=[(X_val, y_val)], callbacks=[lgb.early_stopping(50)])
    
    print("  ✓ LightGBM training complete")
    
    # ========================================================================
    # 3. Random Forest (Baseline)
    # ========================================================================
    print("\n[3/4] Training Random Forest (baseline)...")
    
    models['random_forest'] = RandomForestClassifier(
        n_estimators=100,
        max_depth=30,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=config['random_state'],
        n_jobs=-1,
        verbose=1
    )
    
    models['random_forest'].fit(X_train, y_train)
    
    print("  ✓ Random Forest training complete")
    
    # ========================================================================
    # 4. Stacking Ensemble
    # ========================================================================
    print("\n[4/4] Training Stacking Ensemble...")
    
    estimators = [
        ('xgb', models['xgboost']),
        ('lgb', models['lightgbm']),
        ('rf', models['random_forest'])
    ]
    
    models['stacking'] = StackingClassifier(
        estimators=estimators,
        final_estimator=LogisticRegression(max_iter=1000, random_state=config['random_state']),
        cv=5,
        n_jobs=-1,
        verbose=1
    )
    
    models['stacking'].fit(X_train, y_train)
    
    print("  ✓ Stacking Ensemble training complete")
    
    return models


# ============================================================================
# MODEL EVALUATION
# ============================================================================

def evaluate_models(models, X_test, y_test, label_encoder):
    """
    Comprehensive evaluation of all models.
    
    Args:
        models (dict): Trained models
        X_test, y_test: Test data
        label_encoder: Label encoder for class names
        
    Returns:
        dict: Evaluation results
    """
    print("\n" + "=" * 70)
    print("STEP 5: MODEL EVALUATION")
    print("=" * 70)
    
    results = {}
    
    for model_name, model in models.items():
        print(f"\n{'=' * 70}")
        print(f"Evaluating: {model_name.upper()}")
        print('=' * 70)
        
        # Predictions
        y_pred = model.predict(X_test)
        
        # Metrics
        accuracy = accuracy_score(y_test, y_pred)
        f1_macro = f1_score(y_test, y_pred, average='macro')
        f1_weighted = f1_score(y_test, y_pred, average='weighted')
        precision_macro = precision_score(y_test, y_pred, average='macro')
        recall_macro = recall_score(y_test, y_pred, average='macro')
        mcc = matthews_corrcoef(y_test, y_pred)
        
        # ROC-AUC (multi-class)
        try:
            y_pred_proba = model.predict_proba(X_test)
            roc_auc = roc_auc_score(y_test, y_pred_proba, multi_class='ovr', average='macro')
        except:
            roc_auc = None
        
        # Store results
        results[model_name] = {
            'accuracy': accuracy,
            'f1_macro': f1_macro,
            'f1_weighted': f1_weighted,
            'precision_macro': precision_macro,
            'recall_macro': recall_macro,
            'mcc': mcc,
            'roc_auc': roc_auc,
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
            'classification_report': classification_report(
                y_test, y_pred,
                target_names=label_encoder.classes_,
                output_dict=True
            )
        }
        
        # Print results
        print(f"\nAccuracy:          {accuracy:.4f}")
        print(f"F1-Score (macro):  {f1_macro:.4f}")
        print(f"F1-Score (weighted): {f1_weighted:.4f}")
        print(f"Precision (macro): {precision_macro:.4f}")
        print(f"Recall (macro):    {recall_macro:.4f}")
        print(f"MCC:               {mcc:.4f}")
        if roc_auc:
            print(f"ROC-AUC (macro):   {roc_auc:.4f}")
        
        print(f"\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))
        
        print(f"\nConfusion Matrix:")
        print(confusion_matrix(y_test, y_pred))
    
    return results


# ============================================================================
# SAVE MODELS & RESULTS
# ============================================================================

def save_artifacts(models, results, feature_names, label_encoder, config):
    """
    Save trained models and evaluation results.
    
    Args:
        models (dict): Trained models
        results (dict): Evaluation results
        feature_names (list): Feature names
        label_encoder: Label encoder
        config (dict): Configuration dictionary
    """
    print("\n" + "=" * 70)
    print("STEP 6: SAVING ARTIFACTS")
    print("=" * 70)
    
    # Create directories
    os.makedirs(config['output_dir'], exist_ok=True)
    os.makedirs(config['results_dir'], exist_ok=True)
    
    # Save models
    print("\n[1/3] Saving models...")
    for model_name, model in models.items():
        model_path = os.path.join(config['output_dir'], f'{model_name}_model.pkl')
        joblib.dump(model, model_path, compress=3)
        print(f"  ✓ Saved {model_name} to {model_path}")
    
    # Save feature names and label encoder
    joblib.dump(feature_names, os.path.join(config['output_dir'], 'feature_names_advanced.pkl'))
    joblib.dump(label_encoder, os.path.join(config['output_dir'], 'label_encoder.pkl'))
    print(f"  ✓ Saved feature names and label encoder")
    
    # Save results
    print("\n[2/3] Saving evaluation results...")
    results_path = os.path.join(config['results_dir'], 'model_comparison.json')
    with open(results_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"  ✓ Saved results to {results_path}")
    
    # Save configuration
    print("\n[3/3] Saving configuration...")
    config_path = os.path.join(config['output_dir'], 'training_config.json')
    config_serializable = {k: v for k, v in config.items() if isinstance(v, (int, float, str, bool, type(None)))}
    with open(config_path, 'w') as f:
        json.dump(config_serializable, f, indent=2)
    print(f"  ✓ Saved configuration to {config_path}")
    
    print("\n✓ All artifacts saved successfully!")


# ============================================================================
# MAIN PIPELINE
# ============================================================================

def main():
    """
    Main training pipeline.
    """
    print("\n" + "=" * 70)
    print("PHISHGUARD AI - ADVANCED MODEL TRAINING PIPELINE")
    print("=" * 70)
    print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    # Step 1: Load data and extract features
    X, y, feature_names, label_encoder = load_and_prepare_data(CONFIG)
    
    # Step 2: Split and balance data
    X_train, X_val, X_test, y_train, y_val, y_test = split_and_balance_data(X, y, CONFIG)
    
    # Step 3 & 4: Train models (includes hyperparameter optimization)
    models = train_ensemble_models(X_train, y_train, X_val, y_val, CONFIG)
    
    # Step 5: Evaluate models
    results = evaluate_models(models, X_test, y_test, label_encoder)
    
    # Step 6: Save artifacts
    save_artifacts(models, results, feature_names, label_encoder, CONFIG)
    
    # Final summary
    print("\n" + "=" * 70)
    print("TRAINING COMPLETE!")
    print("=" * 70)
    print(f"End time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("\nModel Performance Summary (F1-Score Macro):")
    for model_name, result in results.items():
        print(f"  {model_name:20s}: {result['f1_macro']:.4f}")
    
    # Identify best model
    best_model = max(results.items(), key=lambda x: x[1]['f1_macro'])
    print(f"\n🏆 Best Model: {best_model[0].upper()} (F1={best_model[1]['f1_macro']:.4f})")
    
    print("\n" + "=" * 70)
    print("Next steps:")
    print("  1. Review results in: results/performance_metrics/")
    print("  2. Generate SHAP visualizations: python src/explainability_analysis.py")
    print("  3. Run stress tests: python src/stress_test.py")
    print("=" * 70)


if __name__ == '__main__':
    main()
