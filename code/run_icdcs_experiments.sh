#!/bin/bash
# ================================================================================
# ICDCS Experiments Deployment Script for GCP
# Target: deepvis-mid (34.64.40.110)
# ================================================================================
set -e

echo "=========================================="
echo "DeepVis ICDCS Experiments Runner"
echo "=========================================="
echo "Started: $(date)"
echo ""

cd ~

# Install dependencies
echo "[1/5] Installing dependencies..."
pip3 install --quiet numpy matplotlib 2>/dev/null || pip install --quiet numpy matplotlib

# Run Experiment 1: Sensitivity Heatmap
echo ""
echo "[2/5] Running Experiment 1: Sensitivity Heatmap..."
python3 ~/exp_sensitivity_heatmap.py 2>&1 | tee ~/exp1_sensitivity.log

# Run Experiment 2: Hyperscale Saturation
echo ""
echo "[3/5] Running Experiment 2: Hyperscale Saturation..."
python3 ~/exp_hyperscale_saturation.py 2>&1 | tee ~/exp2_hyperscale.log

# Run Experiment 3: ROC Curve
echo ""
echo "[4/5] Running Experiment 3: ROC Curve..."
python3 ~/exp_roc_curve.py 2>&1 | tee ~/exp3_roc.log

# Collect results
echo ""
echo "[5/5] Collecting results..."
mkdir -p ~/icdcs_results
mv -f sensitivity_heatmap.csv ~/icdcs_results/ 2>/dev/null || true
mv -f fig8_sensitivity_heatmap.png ~/icdcs_results/ 2>/dev/null || true
mv -f hyperscale_saturation.csv ~/icdcs_results/ 2>/dev/null || true
mv -f fig_hyperscale_saturation.png ~/icdcs_results/ 2>/dev/null || true
mv -f roc_curve_data.csv ~/icdcs_results/ 2>/dev/null || true
mv -f fig9_roc_curve.png ~/icdcs_results/ 2>/dev/null || true

echo ""
echo "=========================================="
echo "ALL EXPERIMENTS COMPLETED!"
echo "=========================================="
echo "Results saved to: ~/icdcs_results/"
ls -la ~/icdcs_results/
echo ""
echo "Finished: $(date)"
