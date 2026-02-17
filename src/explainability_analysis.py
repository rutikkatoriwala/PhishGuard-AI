"""
PhishGuard AI - Explainability Analysis (SHAP)
===============================================
Generate SHAP (SHapley Additive exPlanations) visualizations for
model interpretability and publication-ready figures.

Author: PhishGuard Research Team
Date: 2026-02-17
Version: 2.0.0 (Research Edition)
"""

import pandas as pd
import numpy as np
import joblib
import os
import sys
from pathlib import Path
import matplotlib.pyplot as plt
import seaborn as sns
import shap

# Add src directory to path
sys.path.append(str(Path(__file__).parent))
from advanced_features import extract_features_batch, get_feature_descriptions


# ============================================================================
# CONFIGURATION
# ============================================================================

CONFIG = {
    'model_path': '../models/xgboost_model.pkl',  # Primary model for SHAP
    'data_path': '../malicious_phish_cleaned.csv',
    'feature_names_path': '../models/feature_names_advanced.pkl',
    'label_encoder_path': '../models/label_encoder.pkl',
    'output_dir': '../results/shap_plots',
    'max_samples_shap': 1000,  # Limit for SHAP (computationally expensive)
    'random_state': 42,
}


# ============================================================================
# SHAP ANALYSIS
# ============================================================================

def load_model_and_data(config):
    """
    Load trained model and prepare test data.
    
    Args:
        config (dict): Configuration dictionary
        
    Returns:
        tuple: (model, X_test, y_test, feature_names, label_encoder)
    """
    print("=" * 70)
    print("LOADING MODEL & DATA")
    print("=" * 70)
    
    # Load model
    print(f"\n[1/4] Loading model from {config['model_path']}...")
    model = joblib.load(config['model_path'])
    print("  ✓ Model loaded")
    
    # Load feature names and label encoder
    print(f"\n[2/4] Loading metadata...")
    feature_names = joblib.load(config['feature_names_path'])
    label_encoder = joblib.load(config['label_encoder_path'])
    print(f"  ✓ Features: {len(feature_names)}")
    print(f"  ✓ Classes: {list(label_encoder.classes_)}")
    
    # Load dataset
    print(f"\n[3/4] Loading dataset from {config['data_path']}...")
    df = pd.read_csv(config['data_path'])
    
    # Sample for SHAP (computationally expensive)
    if len(df) > config['max_samples_shap']:
        print(f"  ⚠ Sampling {config['max_samples_shap']} URLs for SHAP analysis...")
        df = df.sample(n=config['max_samples_shap'], random_state=config['random_state'])
    
    print(f"  ✓ Loaded {len(df):,} URLs")
    
    # Extract features
    print(f"\n[4/4] Extracting features...")
    features_list = extract_features_batch(df['url'].tolist(), verbose=True)
    X = pd.DataFrame(features_list)
    y = label_encoder.transform(df['type'])
    
    print(f"  ✓ Feature matrix: {X.shape}")
    
    return model, X, y, feature_names, label_encoder


def generate_shap_explainer(model, X, config):
    """
    Create SHAP explainer for the model.
    
    Args:
        model: Trained model
        X (pd.DataFrame): Feature matrix
        config (dict): Configuration dictionary
        
    Returns:
        tuple: (explainer, shap_values)
    """
    print("\n" + "=" * 70)
    print("GENERATING SHAP EXPLANATIONS")
    print("=" * 70)
    
    print("\n[1/2] Creating SHAP explainer...")
    print("  This may take several minutes...")
    
    # Use TreeExplainer for tree-based models (XGBoost, LightGBM, RF)
    explainer = shap.TreeExplainer(model)
    print("  ✓ Explainer created")
    
    print("\n[2/2] Computing SHAP values...")
    shap_values = explainer.shap_values(X)
    print("  ✓ SHAP values computed")
    print(f"  Shape: {np.array(shap_values).shape}")
    
    return explainer, shap_values


def plot_shap_summary(shap_values, X, feature_names, label_encoder, output_dir):
    """
    Generate SHAP summary plot (beeswarm).
    
    Args:
        shap_values: SHAP values
        X (pd.DataFrame): Feature matrix
        feature_names (list): Feature names
        label_encoder: Label encoder
        output_dir (str): Output directory
    """
    print("\n" + "=" * 70)
    print("PLOT 1: SHAP SUMMARY (BEESWARM)")
    print("=" * 70)
    
    os.makedirs(output_dir, exist_ok=True)
    
    # For multi-class, plot each class
    num_classes = len(label_encoder.classes_)
    
    if num_classes > 2:
        # Multi-class: plot each class separately
        for class_idx, class_name in enumerate(label_encoder.classes_):
            print(f"\n  Generating summary plot for class: {class_name}")
            
            plt.figure(figsize=(12, 8))
            shap.summary_plot(
                shap_values[class_idx],
                X,
                feature_names=feature_names,
                show=False,
                max_display=20
            )
            plt.title(f'SHAP Summary Plot - {class_name.upper()} Class', fontsize=16, fontweight='bold')
            plt.tight_layout()
            
            output_path = os.path.join(output_dir, f'shap_summary_{class_name}.png')
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            print(f"    ✓ Saved to {output_path}")
    else:
        # Binary classification
        plt.figure(figsize=(12, 8))
        shap.summary_plot(
            shap_values,
            X,
            feature_names=feature_names,
            show=False,
            max_display=20
        )
        plt.title('SHAP Summary Plot', fontsize=16, fontweight='bold')
        plt.tight_layout()
        
        output_path = os.path.join(output_dir, 'shap_summary.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"  ✓ Saved to {output_path}")


def plot_shap_feature_importance(shap_values, X, feature_names, label_encoder, output_dir):
    """
    Generate SHAP feature importance bar plot.
    
    Args:
        shap_values: SHAP values
        X (pd.DataFrame): Feature matrix
        feature_names (list): Feature names
        label_encoder: Label encoder
        output_dir (str): Output directory
    """
    print("\n" + "=" * 70)
    print("PLOT 2: SHAP FEATURE IMPORTANCE")
    print("=" * 70)
    
    num_classes = len(label_encoder.classes_)
    
    if num_classes > 2:
        # Multi-class: average SHAP values across classes
        print("\n  Computing mean absolute SHAP values across all classes...")
        
        # Stack SHAP values for all classes
        shap_values_stacked = np.abs(np.array(shap_values)).mean(axis=0)
        
        # Calculate mean importance per feature
        feature_importance = np.abs(shap_values_stacked).mean(axis=0)
        
        # Create DataFrame
        importance_df = pd.DataFrame({
            'feature': feature_names,
            'importance': feature_importance
        }).sort_values('importance', ascending=False)
        
        # Plot top 20
        plt.figure(figsize=(10, 12))
        top_features = importance_df.head(20)
        
        plt.barh(range(len(top_features)), top_features['importance'], color='steelblue')
        plt.yticks(range(len(top_features)), top_features['feature'])
        plt.xlabel('Mean |SHAP Value| (Average across all classes)', fontsize=12)
        plt.ylabel('Feature', fontsize=12)
        plt.title('Top 20 Features by SHAP Importance', fontsize=16, fontweight='bold')
        plt.gca().invert_yaxis()
        plt.grid(axis='x', alpha=0.3)
        plt.tight_layout()
        
        output_path = os.path.join(output_dir, 'shap_feature_importance.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"  ✓ Saved to {output_path}")
        
        # Save importance table
        table_path = os.path.join(output_dir, 'feature_importance_table.csv')
        importance_df.to_csv(table_path, index=False)
        print(f"  ✓ Saved importance table to {table_path}")
        
        # Print top 10
        print("\n  Top 10 Most Important Features:")
        for idx, row in importance_df.head(10).iterrows():
            print(f"    {row['feature']:30s}: {row['importance']:.4f}")
    
    else:
        # Binary classification
        feature_importance = np.abs(shap_values).mean(axis=0)
        
        importance_df = pd.DataFrame({
            'feature': feature_names,
            'importance': feature_importance
        }).sort_values('importance', ascending=False)
        
        plt.figure(figsize=(10, 12))
        top_features = importance_df.head(20)
        
        plt.barh(range(len(top_features)), top_features['importance'], color='steelblue')
        plt.yticks(range(len(top_features)), top_features['feature'])
        plt.xlabel('Mean |SHAP Value|', fontsize=12)
        plt.ylabel('Feature', fontsize=12)
        plt.title('Top 20 Features by SHAP Importance', fontsize=16, fontweight='bold')
        plt.gca().invert_yaxis()
        plt.grid(axis='x', alpha=0.3)
        plt.tight_layout()
        
        output_path = os.path.join(output_dir, 'shap_feature_importance.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"  ✓ Saved to {output_path}")


def plot_shap_dependence(shap_values, X, feature_names, label_encoder, output_dir, top_n=5):
    """
    Generate SHAP dependence plots for top features.
    
    Args:
        shap_values: SHAP values
        X (pd.DataFrame): Feature matrix
        feature_names (list): Feature names
        label_encoder: Label encoder
        output_dir (str): Output directory
        top_n (int): Number of top features to plot
    """
    print("\n" + "=" * 70)
    print(f"PLOT 3: SHAP DEPENDENCE PLOTS (TOP {top_n} FEATURES)")
    print("=" * 70)
    
    # Calculate feature importance to identify top features
    num_classes = len(label_encoder.classes_)
    
    if num_classes > 2:
        shap_values_stacked = np.abs(np.array(shap_values)).mean(axis=0)
        feature_importance = np.abs(shap_values_stacked).mean(axis=0)
    else:
        feature_importance = np.abs(shap_values).mean(axis=0)
    
    # Get top features
    top_indices = np.argsort(feature_importance)[-top_n:][::-1]
    top_feature_names = [feature_names[i] for i in top_indices]
    
    print(f"\n  Top {top_n} features for dependence plots:")
    for i, feat in enumerate(top_feature_names, 1):
        print(f"    {i}. {feat}")
    
    # Create dependence plots
    dependence_dir = os.path.join(output_dir, 'dependence_plots')
    os.makedirs(dependence_dir, exist_ok=True)
    
    for feat_idx, feat_name in zip(top_indices, top_feature_names):
        print(f"\n  Generating dependence plot for: {feat_name}")
        
        if num_classes > 2:
            # Multi-class: plot for first class (phishing or most important)
            class_idx = 0  # Adjust based on your class order
            
            plt.figure(figsize=(10, 6))
            shap.dependence_plot(
                feat_idx,
                shap_values[class_idx],
                X,
                feature_names=feature_names,
                show=False
            )
            plt.title(f'SHAP Dependence Plot: {feat_name}\n(Class: {label_encoder.classes_[class_idx]})',
                     fontsize=14, fontweight='bold')
            plt.tight_layout()
            
            output_path = os.path.join(dependence_dir, f'dependence_{feat_name}.png')
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            print(f"    ✓ Saved to {output_path}")
        
        else:
            # Binary classification
            plt.figure(figsize=(10, 6))
            shap.dependence_plot(
                feat_idx,
                shap_values,
                X,
                feature_names=feature_names,
                show=False
            )
            plt.title(f'SHAP Dependence Plot: {feat_name}', fontsize=14, fontweight='bold')
            plt.tight_layout()
            
            output_path = os.path.join(dependence_dir, f'dependence_{feat_name}.png')
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            print(f"    ✓ Saved to {output_path}")


def plot_shap_waterfall(explainer, shap_values, X, label_encoder, output_dir, num_samples=5):
    """
    Generate SHAP waterfall plots for individual predictions.
    
    Args:
        explainer: SHAP explainer
        shap_values: SHAP values
        X (pd.DataFrame): Feature matrix
        label_encoder: Label encoder
        output_dir (str): Output directory
        num_samples (int): Number of sample predictions to visualize
    """
    print("\n" + "=" * 70)
    print(f"PLOT 4: SHAP WATERFALL PLOTS ({num_samples} SAMPLES)")
    print("=" * 70)
    
    waterfall_dir = os.path.join(output_dir, 'waterfall_plots')
    os.makedirs(waterfall_dir, exist_ok=True)
    
    num_classes = len(label_encoder.classes_)
    
    # Select random samples
    sample_indices = np.random.choice(len(X), size=min(num_samples, len(X)), replace=False)
    
    for i, sample_idx in enumerate(sample_indices, 1):
        print(f"\n  Generating waterfall plot for sample {i}/{num_samples} (index {sample_idx})")
        
        if num_classes > 2:
            # Multi-class: plot for each class
            for class_idx, class_name in enumerate(label_encoder.classes_):
                plt.figure(figsize=(10, 8))
                
                # Create explanation object
                shap_explanation = shap.Explanation(
                    values=shap_values[class_idx][sample_idx],
                    base_values=explainer.expected_value[class_idx],
                    data=X.iloc[sample_idx].values,
                    feature_names=X.columns.tolist()
                )
                
                shap.waterfall_plot(shap_explanation, show=False)
                plt.title(f'SHAP Waterfall Plot - Sample {i}\nClass: {class_name.upper()}',
                         fontsize=14, fontweight='bold')
                plt.tight_layout()
                
                output_path = os.path.join(waterfall_dir, f'waterfall_sample{i}_{class_name}.png')
                plt.savefig(output_path, dpi=300, bbox_inches='tight')
                plt.close()
                
                print(f"    ✓ Saved {class_name} to {output_path}")
        
        else:
            # Binary classification
            plt.figure(figsize=(10, 8))
            
            shap_explanation = shap.Explanation(
                values=shap_values[sample_idx],
                base_values=explainer.expected_value,
                data=X.iloc[sample_idx].values,
                feature_names=X.columns.tolist()
            )
            
            shap.waterfall_plot(shap_explanation, show=False)
            plt.title(f'SHAP Waterfall Plot - Sample {i}', fontsize=14, fontweight='bold')
            plt.tight_layout()
            
            output_path = os.path.join(waterfall_dir, f'waterfall_sample{i}.png')
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            print(f"    ✓ Saved to {output_path}")


# ============================================================================
# MAIN PIPELINE
# ============================================================================

def main():
    """
    Main SHAP analysis pipeline.
    """
    print("\n" + "=" * 70)
    print("PHISHGUARD AI - SHAP EXPLAINABILITY ANALYSIS")
    print("=" * 70)
    
    # Load model and data
    model, X, y, feature_names, label_encoder = load_model_and_data(CONFIG)
    
    # Generate SHAP explainer
    explainer, shap_values = generate_shap_explainer(model, X, CONFIG)
    
    # Generate visualizations
    plot_shap_summary(shap_values, X, feature_names, label_encoder, CONFIG['output_dir'])
    plot_shap_feature_importance(shap_values, X, feature_names, label_encoder, CONFIG['output_dir'])
    plot_shap_dependence(shap_values, X, feature_names, label_encoder, CONFIG['output_dir'], top_n=5)
    plot_shap_waterfall(explainer, shap_values, X, label_encoder, CONFIG['output_dir'], num_samples=3)
    
    # Final summary
    print("\n" + "=" * 70)
    print("SHAP ANALYSIS COMPLETE!")
    print("=" * 70)
    print(f"\nAll visualizations saved to: {CONFIG['output_dir']}")
    print("\nGenerated plots:")
    print("  1. SHAP Summary (Beeswarm) - shows feature impact distribution")
    print("  2. Feature Importance Bar Chart - ranks features by importance")
    print("  3. Dependence Plots - shows feature interactions (top 5)")
    print("  4. Waterfall Plots - explains individual predictions (3 samples)")
    print("\n" + "=" * 70)


if __name__ == '__main__':
    # Set style for publication-quality plots
    sns.set_style('whitegrid')
    plt.rcParams['font.family'] = 'sans-serif'
    plt.rcParams['font.sans-serif'] = ['Arial', 'DejaVu Sans']
    plt.rcParams['font.size'] = 10
    
    main()
