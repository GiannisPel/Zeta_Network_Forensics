import os
import sys
import sqlite3
import json
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from collections import defaultdict

#Local project imports
from ml_anomaly   import extract_features, N_FEATURES, MODEL_PATH

DB_PATH       = os.environ.get(
    "NET_DB_PATH", "/var/lib/memory_service/net/net.db"
)
MIN_SAMPLES   = 500    #refuse to train on too little data
CONTAMINATION = 0.02   #expected fraction of anomalies in training data
N_ESTIMATORS  = 200    #number of trees in the forest

#FIXED: In Python, {} creates an empty dict. We must use set() for an empty set.
EXCLUDE_CAPTURES: set[str] = set() 

#If non-empty, train ONLY on these captures and ignore everything else.
INCLUDE_ONLY_CAPTURES: set[str] = set()

print(f"Loading packets from {DB_PATH} ...")

if not os.path.exists(DB_PATH):
    print(f"Error: Database not found at {DB_PATH}")
    sys.exit(1)

conn = sqlite3.connect(DB_PATH)

#First show what captures are available so the user can make informed choices
available = conn.execute(
    "SELECT capture_id, COUNT(*) as n FROM net_memories "
    "GROUP BY capture_id ORDER BY n DESC"
).fetchall()

print(f"\nCaptures available in database:")
for cap_id, count in available:
    mode = ""
    if INCLUDE_ONLY_CAPTURES:
        mode = " ✓ INCLUDED" if cap_id in INCLUDE_ONLY_CAPTURES else " ✗ excluded"
    elif cap_id in EXCLUDE_CAPTURES:
        mode = " ✗ EXCLUDED"
    else:
        mode = " ✓ included"
    print(f"  {cap_id:<50} {count:>6} packets{mode}")

#Interactive selection

if not INCLUDE_ONLY_CAPTURES and not EXCLUDE_CAPTURES:
    print(
        "\nNo capture filter configured.\n"
        "Would you like to interactively select which captures to include?\n"
        "  y = yes, choose captures interactively\n"
        "  n = no,  use all captures\n"
        "  q = quit, abandon training\n"
    )
    choice = input("Choice [y/n/q]: ").strip().lower()

    if choice == 'q':
        print("Training abandoned.")
        conn.close()
        sys.exit(0)

    if choice == "y":
        print(
            "\nFor each capture, press ENTER or type 'y' to include, "
            "type 'n' to exclude, or 'q' to cancel and exit:\n"
        )
        for cap_id, count in available:
            answer = input(
                f"  Include '{cap_id}' ({count} packets)? [Y/n/q]: "
            ).strip().lower()
            
            if answer == 'q':
                print("Training abandoned.")
                conn.close()
                sys.exit(0)
            elif answer in {"n", "no"}:
                EXCLUDE_CAPTURES.add(cap_id)
                print(f"    → excluded")
            else:
                print(f"    → included")

        print()
        if EXCLUDE_CAPTURES:
            print(f"Excluded captures: {EXCLUDE_CAPTURES}")
        else:
            print("All captures included.")

#Build the SQL filter
if INCLUDE_ONLY_CAPTURES:
    placeholders = ",".join("?" * len(INCLUDE_ONLY_CAPTURES))
    rows = conn.execute(
        f"SELECT capture_id, meta_json FROM net_memories "
        f"WHERE capture_id IN ({placeholders}) "
        f"ORDER BY created_at ASC",
        list(INCLUDE_ONLY_CAPTURES),
    ).fetchall()
    filter_desc = f"INCLUDE_ONLY: {INCLUDE_ONLY_CAPTURES}"

elif EXCLUDE_CAPTURES:
    placeholders = ",".join("?" * len(EXCLUDE_CAPTURES))
    rows = conn.execute(
        f"SELECT capture_id, meta_json FROM net_memories "
        f"WHERE capture_id NOT IN ({placeholders}) "
        f"ORDER BY created_at ASC",
        list(EXCLUDE_CAPTURES),
    ).fetchall()
    filter_desc = f"EXCLUDE: {EXCLUDE_CAPTURES}"

else:
    rows = conn.execute(
        "SELECT capture_id, meta_json FROM net_memories ORDER BY created_at ASC"
    ).fetchall()
    filter_desc = "all captures"

conn.close()

print(f"\nFilter: {filter_desc}")
print(f"Rows selected for training: {len(rows)}")

#Feature extraction

features: list = []
per_capture_counts: dict[str, int] = defaultdict(int)
skipped = 0

for cap_id, meta_json in rows:
    try:
        meta = json.loads(meta_json)
    except Exception:
        skipped += 1
        continue

    if "layers" not in meta or "packet" not in meta:
        skipped += 1
        continue

    flow_stats = meta.get("flow", {}) if isinstance(meta.get("flow", {}), dict) else {}

    try:
        vec = extract_features(meta, flow_stats)
    except Exception:
        skipped += 1
        continue

    if len(vec) != N_FEATURES:
        skipped += 1
        continue

    features.append(vec)
    per_capture_counts[cap_id] += 1

print(f"\nPackets per capture used for training:")
for cap_id, count in sorted(per_capture_counts.items(), key=lambda x: -x[1]):
    print(f"  {cap_id:<50} {count:>6} packets")

print(f"\nTotal: {len(features)} packets used ({skipped} skipped)")

if len(features) < MIN_SAMPLES:
    print(f"Error: Not enough packet data for training (Need {MIN_SAMPLES}, got {len(features)}).")
    sys.exit(1)

#Train

X = np.array(features, dtype=np.float32)

print(f"\nFeature matrix shape: {X.shape}")

print(f"\nTraining IsolationForest "
      f"(n_estimators={N_ESTIMATORS}, contamination={CONTAMINATION}) ...")

pipeline = Pipeline([
    ("scaler", StandardScaler()),
    ("iforest", IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=CONTAMINATION,
        random_state=42,
        n_jobs=1,
    )),
])

pipeline.fit(X)

train_preds = pipeline.predict(X)
n_anomalies = int((train_preds == -1).sum())
print(f"  Anomalies flagged in training data: "
      f"{n_anomalies} / {len(features)} "
      f"({100 * n_anomalies / len(features):.1f}%)")

joblib.dump(pipeline, MODEL_PATH)
print(f"\nModel saved to {MODEL_PATH}")
print("Done. Restart the service to load the new model.")
