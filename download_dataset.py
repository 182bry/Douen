import os
import sys
import zipfile
import shutil
import subprocess

# ─────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────

OUTPUT_DIR = os.path.join("data", "raw", "cicids2017")

# Kaggle dataset slug — this is the most complete, well-maintained mirror
# with all 8 original MachineLearningCSV files
KAGGLE_DATASET = "cicdataset/cicids2017"

# Expected CSV files after extraction (for validation)
EXPECTED_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def check_kaggle_installed():
    try:
        import kaggle
        return True
    except ImportError:
        return False


def check_kaggle_credentials():
    kaggle_json = os.path.expanduser(os.path.join("~", ".kaggle", "kaggle.json"))
    if sys.platform == "win32":
        kaggle_json = os.path.join(os.environ.get("USERPROFILE", ""), ".kaggle", "kaggle.json")
    return os.path.exists(kaggle_json)


def already_downloaded():
    if not os.path.isdir(OUTPUT_DIR):
        return False
    existing = [f for f in os.listdir(OUTPUT_DIR) if f.endswith(".csv")]
    return len(existing) >= 7   # at least 7 of 8 files


def validate_files():
    existing = set(os.listdir(OUTPUT_DIR))
    missing = [f for f in EXPECTED_FILES if f not in existing]
    return missing


def print_manual_instructions():
    print("""
╔══════════════════════════════════════════════════════════════╗
║           MANUAL DOWNLOAD INSTRUCTIONS                       ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Option A — UNB (Official source, no account needed):        ║
║    1. Go to:                                                 ║
║       https://www.unb.ca/cic/datasets/ids-2017.html          ║
║    2. Click "MachineLearningCSV.zip"                         ║
║    3. Unzip and place the 8 CSV files into:                  ║
║       data/raw/cicids2017/                                   ║
║                                                              ║
║  Option B — Kaggle (faster, requires free account):          ║
║    1. Sign up at https://www.kaggle.com (free)               ║
║    2. Go to: https://www.kaggle.com/settings                 ║
║    3. Scroll to "API" → "Create New Token"                   ║
║       (downloads kaggle.json)                                ║
║    4. Move kaggle.json to:                                   ║
║       Linux/Mac : ~/.kaggle/kaggle.json                      ║
║       Windows   : C:\\Users\\YOU\\.kaggle\\kaggle.json       ║
║    5. pip install kaggle                                     ║
║    6. python download_dataset.py                             ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
""")


# ─────────────────────────────────────────────────────────────
# Download
# ─────────────────────────────────────────────────────────────

def download_via_kaggle():
    print(f"Downloading dataset: {KAGGLE_DATASET}")
    print(f"Destination        : {OUTPUT_DIR}")
    print("This may take a few minutes (~500 MB)...\n")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Download zip to a temp folder then extract
    tmp_dir = os.path.join("data", "raw", "_tmp_download")
    os.makedirs(tmp_dir, exist_ok=True)

    result = subprocess.run(
        [
            sys.executable, "-m", "kaggle", "datasets", "download",
            "-d", KAGGLE_DATASET,
            "-p", tmp_dir,
            "--unzip"
        ],
        check=False
    )

    if result.returncode != 0:
        print("\n[ERROR] Kaggle download failed.")
        print("Check that your kaggle.json credentials are correct.")
        print_manual_instructions()
        shutil.rmtree(tmp_dir, ignore_errors=True)
        sys.exit(1)

    # Move CSV files to OUTPUT_DIR (they may be in a subdirectory)
    csv_count = 0
    for root, dirs, files in os.walk(tmp_dir):
        for f in files:
            if f.endswith(".csv"):
                src = os.path.join(root, f)
                dst = os.path.join(OUTPUT_DIR, f)
                shutil.move(src, dst)
                print(f"  Moved: {f}")
                csv_count += 1

    shutil.rmtree(tmp_dir, ignore_errors=True)

    if csv_count == 0:
        print("\n[ERROR] No CSV files found after download/extraction.")
        print_manual_instructions()
        sys.exit(1)

    return csv_count


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  CICIDS2017 Dataset Downloader")
    print("=" * 60)

    # Already have the files?
    if already_downloaded():
        print(f"\n[OK] Files already present in {OUTPUT_DIR}")
        missing = validate_files()
        if missing:
            print(f"     Warning: {len(missing)} expected file(s) not found:")
            for f in missing:
                print(f"       - {f}")
        else:
            print("     All 8 expected CSV files are present.")
        print("\nNothing to do. Run ingest.py to proceed.")
        return

    # Check kaggle is installed
    if not check_kaggle_installed():
        print("\n[ERROR] The 'kaggle' package is not installed.")
        print("  Fix: pip install kaggle")
        print_manual_instructions()
        sys.exit(1)

    # Check credentials exist
    if not check_kaggle_credentials():
        print("\n[ERROR] Kaggle credentials (kaggle.json) not found.")
        print_manual_instructions()
        sys.exit(1)

    # Download
    csv_count = download_via_kaggle()

    # Validate
    print(f"\nDownload complete. {csv_count} CSV file(s) placed in {OUTPUT_DIR}")
    missing = validate_files()
    if missing:
        print(f"\nWarning: {len(missing)} expected file(s) not found:")
        for f in missing:
            print(f"  - {f}")
        print("The dataset mirror may use different filenames — check your ingest.py")
    else:
        print("All 8 expected CICIDS2017 files verified.")

    print("\n" + "=" * 60)
    print("  Next step:")
    print("    python run_pipeline.py")
    print("=" * 60)


if __name__ == "__main__":
    main()