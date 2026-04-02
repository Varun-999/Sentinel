from huggingface_hub import list_datasets

datasets = list_datasets(search="CVEFixes")
for ds in datasets:
    print(ds.id)
