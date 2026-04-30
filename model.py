import math

WEIGHTS = {
    "entropy": 1.2,
    "uniform_dist": -1.0,
    "write_burst": 1.0,
    "dir_spread": 1.2,
    "rename_burst": 2.2,
    "suspicious_rename_target": 5.0,
    "header_mismatch": 2.0,
    "files_per_sec": 1.25,
    "extension_change_ratio": 2.5,
}
BIAS = -4.0


def sigmoid(x):
    return 1 / (1 + math.exp(-max(min(x, 10), -10)))


def predict_proba(features):
    return sigmoid(BIAS + sum(WEIGHTS[k] * v for k, v in features.items()))
