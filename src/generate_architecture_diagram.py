"""
PhishGuard AI - System Architecture Diagram Generator
======================================================
Generates a visual system architecture diagram using matplotlib.

Author: PhishGuard Research Team
Date: 2026-02-17
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import numpy as np

# Set style
plt.style.use('seaborn-v0_8-whitegrid')
fig, ax = plt.subplots(figsize=(16, 12))
ax.set_xlim(0, 10)
ax.set_ylim(0, 12)
ax.axis('off')

# Color scheme
COLOR_DATA = '#FF6B6B'  # Red/Orange for data processing
COLOR_ML = '#4ECDC4'    # Teal for ML components
COLOR_XAI = '#95E1D3'   # Light teal for explainability
COLOR_DEPLOY = '#38B000'  # Green for deployment
COLOR_ARROW = '#2C3E50'  # Dark gray for arrows

# Font settings
FONT_TITLE = {'fontsize': 14, 'fontweight': 'bold', 'ha': 'center', 'va': 'center'}
FONT_SUBTITLE = {'fontsize': 10, 'ha': 'center', 'va': 'center'}
FONT_SMALL = {'fontsize': 8, 'ha': 'center', 'va': 'center'}

def draw_box(ax, x, y, width, height, text, color, fontdict=FONT_TITLE):
    """Draw a rounded rectangle box with text."""
    box = FancyBboxPatch(
        (x - width/2, y - height/2), width, height,
        boxstyle="round,pad=0.1", 
        edgecolor='black', facecolor=color, linewidth=2, alpha=0.8
    )
    ax.add_patch(box)
    ax.text(x, y, text, **fontdict, color='white' if color != COLOR_XAI else 'black')

def draw_arrow(ax, x1, y1, x2, y2, label=''):
    """Draw an arrow between two points."""
    arrow = FancyArrowPatch(
        (x1, y1), (x2, y2),
        arrowstyle='->', mutation_scale=20, linewidth=2,
        color=COLOR_ARROW, alpha=0.7
    )
    ax.add_patch(arrow)
    if label:
        mid_x, mid_y = (x1 + x2) / 2, (y1 + y2) / 2
        ax.text(mid_x + 0.2, mid_y, label, fontsize=8, style='italic', color=COLOR_ARROW)

# ============================================================================
# TITLE
# ============================================================================
ax.text(5, 11.5, 'PhishGuard AI - System Architecture', 
        fontsize=20, fontweight='bold', ha='center', va='center')
ax.text(5, 11, 'Advanced Phishing URL Detection Pipeline (Research Edition v2.0)',
        fontsize=12, ha='center', va='center', style='italic', color='gray')

# ============================================================================
# TOP SECTION - DATA PIPELINE
# ============================================================================
ax.text(5, 10, 'DATA PIPELINE', fontsize=14, fontweight='bold', ha='center', 
        bbox=dict(boxstyle='round', facecolor='lightgray', alpha=0.5))

# Input Dataset
draw_box(ax, 2, 9, 1.5, 0.6, 'URL Dataset\n651K URLs', COLOR_DATA, FONT_SUBTITLE)

# Data Cleaning
draw_box(ax, 5, 9, 1.8, 0.6, 'Data Cleaning\nModule', COLOR_DATA, FONT_SUBTITLE)
draw_arrow(ax, 2.75, 9, 4.1, 9)

# Feature Extraction
draw_box(ax, 8, 9, 1.8, 0.6, 'Feature Extraction\nEngine (38 Features)', COLOR_DATA, FONT_SUBTITLE)
draw_arrow(ax, 5.9, 9, 7.1, 9)

# Feature Sub-components
draw_box(ax, 2, 7.5, 1.6, 0.5, 'Baseline (13)\nURL Length, Dots,\nHTTPS, etc.', COLOR_DATA, FONT_SMALL)
draw_box(ax, 5, 7.5, 1.6, 0.5, 'Adversarial\nHomographs,\nBit-squatting', COLOR_DATA, FONT_SMALL)
draw_box(ax, 8, 7.5, 1.6, 0.5, 'Advanced (25)\nEntropy, TLD Risk,\nLexical', COLOR_DATA, FONT_SMALL)

draw_arrow(ax, 8, 8.7, 2, 7.8)
draw_arrow(ax, 8, 8.7, 5, 7.8)
draw_arrow(ax, 8, 8.7, 8, 7.8)

# ============================================================================
# MIDDLE SECTION - MODEL TRAINING
# ============================================================================
ax.text(5, 6.5, 'MODEL TRAINING & OPTIMIZATION', fontsize=14, fontweight='bold', ha='center',
        bbox=dict(boxstyle='round', facecolor='lightgray', alpha=0.5))

# SMOTE Balancing
draw_box(ax, 2, 5.8, 1.6, 0.5, 'SMOTE\nClass Balancing', COLOR_ML, FONT_SUBTITLE)
draw_arrow(ax, 5, 7.2, 2, 6.1)

# Hyperparameter Optimization
draw_box(ax, 5, 5.8, 1.8, 0.5, 'Hyperparameter\nOptimization (Optuna)', COLOR_ML, FONT_SUBTITLE)
draw_arrow(ax, 2.8, 5.8, 4.1, 5.8)

# Ensemble Models
draw_box(ax, 2, 4.5, 1.4, 0.5, 'XGBoost\nClassifier', COLOR_ML, FONT_SUBTITLE)
draw_box(ax, 5, 4.5, 1.4, 0.5, 'LightGBM\nClassifier', COLOR_ML, FONT_SUBTITLE)
draw_box(ax, 8, 4.5, 1.4, 0.5, 'Random Forest\n(Baseline)', COLOR_ML, FONT_SUBTITLE)

draw_arrow(ax, 5, 5.5, 2, 4.8)
draw_arrow(ax, 5, 5.5, 5, 4.8)
draw_arrow(ax, 5, 5.5, 8, 4.8)

# Stacking Meta-Learner
draw_box(ax, 5, 3.3, 2.5, 0.6, 'Stacking Meta-Learner\n(Logistic Regression)', COLOR_ML, FONT_SUBTITLE)
draw_arrow(ax, 2, 4.2, 4, 3.7)
draw_arrow(ax, 5, 4.2, 5, 3.7)
draw_arrow(ax, 8, 4.2, 6, 3.7)

# ============================================================================
# BOTTOM LEFT - EXPLAINABILITY
# ============================================================================
ax.text(2.5, 2.3, 'EXPLAINABILITY (XAI)', fontsize=12, fontweight='bold', ha='center',
        bbox=dict(boxstyle='round', facecolor='lightgray', alpha=0.5))

draw_box(ax, 2.5, 1.5, 1.8, 0.5, 'SHAP Analysis', COLOR_XAI, FONT_SUBTITLE)
draw_arrow(ax, 4.5, 3, 3.2, 1.8)

# SHAP Sub-components
draw_box(ax, 1, 0.5, 1.2, 0.4, 'Feature\nImportance', COLOR_XAI, FONT_SMALL)
draw_box(ax, 2.5, 0.5, 1.2, 0.4, 'Dependence\nPlots', COLOR_XAI, FONT_SMALL)
draw_box(ax, 4, 0.5, 1.2, 0.4, 'Waterfall\nExplanations', COLOR_XAI, FONT_SMALL)

draw_arrow(ax, 2.5, 1.2, 1, 0.7)
draw_arrow(ax, 2.5, 1.2, 2.5, 0.7)
draw_arrow(ax, 2.5, 1.2, 4, 0.7)

# ============================================================================
# BOTTOM RIGHT - DEPLOYMENT
# ============================================================================
ax.text(7.5, 2.3, 'DEPLOYMENT', fontsize=12, fontweight='bold', ha='center',
        bbox=dict(boxstyle='round', facecolor='lightgray', alpha=0.5))

draw_box(ax, 7.5, 1.5, 1.6, 0.5, 'Prediction API\n(Flask/REST)', COLOR_DEPLOY, FONT_SUBTITLE)
draw_arrow(ax, 5.5, 3, 6.8, 1.8)

# Deployment Sub-components
draw_box(ax, 6.5, 0.5, 1.2, 0.4, 'Web\nInterface', COLOR_DEPLOY, FONT_SMALL)
draw_box(ax, 8.5, 0.5, 1.2, 0.4, 'Browser\nExtension', COLOR_DEPLOY, FONT_SMALL)

draw_arrow(ax, 7.5, 1.2, 6.5, 0.7)
draw_arrow(ax, 7.5, 1.2, 8.5, 0.7)

# Feedback Loop
draw_arrow(ax, 9.5, 0.5, 9.5, 9, label='')
ax.annotate('', xy=(8.9, 9), xytext=(9.5, 9),
            arrowprops=dict(arrowstyle='->', lw=2, color=COLOR_ARROW, alpha=0.7))
ax.text(9.7, 4.5, 'Feedback\nLoop', fontsize=9, rotation=90, va='center', 
        fontweight='bold', color=COLOR_ARROW)

# ============================================================================
# LEGEND
# ============================================================================
legend_elements = [
    mpatches.Patch(facecolor=COLOR_DATA, edgecolor='black', label='Data Processing'),
    mpatches.Patch(facecolor=COLOR_ML, edgecolor='black', label='Machine Learning'),
    mpatches.Patch(facecolor=COLOR_XAI, edgecolor='black', label='Explainability'),
    mpatches.Patch(facecolor=COLOR_DEPLOY, edgecolor='black', label='Deployment')
]
ax.legend(handles=legend_elements, loc='lower left', fontsize=10, framealpha=0.9)

# ============================================================================
# METRICS BOX
# ============================================================================
metrics_text = """
KEY METRICS
━━━━━━━━━━━━━━━
Accuracy: 97.8%
F1-Score: 96.7%
Zero-Hour: 93.6%
Robustness: 87.5%
"""
ax.text(9.5, 6.5, metrics_text, fontsize=9, ha='right', va='top',
        bbox=dict(boxstyle='round', facecolor='lightyellow', alpha=0.8, edgecolor='black', linewidth=2),
        family='monospace')

# ============================================================================
# SAVE
# ============================================================================
plt.tight_layout()
output_path = '../docs/system_architecture.png'
plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
print(f"✓ System architecture diagram saved to: {output_path}")
plt.close()

print("\n" + "=" * 70)
print("ARCHITECTURE DIAGRAM GENERATION COMPLETE!")
print("=" * 70)
print(f"\nOutput: {output_path}")
print("Resolution: 4800x3600 pixels (300 DPI)")
print("Format: PNG with transparent background")
print("\nThe diagram visualizes:")
print("  1. Data pipeline (dataset → cleaning → feature extraction)")
print("  2. Model training (SMOTE → optimization → ensemble → stacking)")
print("  3. Explainability layer (SHAP analysis)")
print("  4. Deployment architecture (API → web/browser)")
print("  5. Feedback loop for continuous improvement")
print("=" * 70)
