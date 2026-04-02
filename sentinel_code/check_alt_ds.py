from datasets import load_dataset
import sys

def check_ds(ds_name, split='train'):
    try:
        ds = load_dataset(ds_name, split=split)
        print(f"[{ds_name}] Columns: {ds.column_names}")
        print(f"Sample 0:")
        for k, v in ds[0].items():
            print(f"{k}: {str(v)[:150]}")
        print("-" * 40)
    except Exception as e:
        print(f"Error loading {ds_name}: {e}")

check_ds("starsofchance/CVEfixes_v1.0.8")
check_ds("MickyMike/cvefixes_bigvul")
