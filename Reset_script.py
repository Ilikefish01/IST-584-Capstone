import os
import shutil

CLEAN = r"C:\Users\kritt\Desktop\PSU\Term 8\IST 584\CleanData"
LIVE = r"C:\Users\kritt\Desktop\PSU\Term 8\IST 584\TestFolder"


def reset_dataset():
    if os.path.exists(LIVE):
        shutil.rmtree(LIVE)
    shutil.copytree(CLEAN, LIVE)
    print("Dataset reset complete.")


reset_dataset()
