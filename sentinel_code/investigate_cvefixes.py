from datasets import load_dataset

def main():
    print("Loading dataset...")
    ds = load_dataset("DetectVul/CVEFixes")
    print(ds)
    print("Columns in train:")
    print(ds['train'].column_names)
    print("Sample 0:")
    for k, v in ds['train'][0].items():
        print(f"{k}: {str(v)[:100]}")

if __name__ == "__main__":
    main()
