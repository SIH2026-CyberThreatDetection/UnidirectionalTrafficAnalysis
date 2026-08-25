from pathlib import Path

TRAIN_PATH = Path("data/splits/train/train.parquet")
TARGET = "project_label"

def main():
    print("ML training pipeline initialized.")
    print(f"Expected data: {TRAIN_PATH}")
    print(f"Target: {TARGET}")
    print("Next: load the approved feature dataset.")

if __name__ == "__main__":
    main()
