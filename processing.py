from datetime import datetime
import pandas as pd
import re
import os


ALLOWED_EXTENSIONS = {"txt", "csv"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_filename():
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return f"resultat_{ts}.csv"


def process_txt_to_csv(input_path, output_path):
    if os.path.getsize(input_path) == 0:
        raise ValueError("Fichier TXT vide")

    pattern = r"^(27|28|29)\d{4}"
    cleaned = []
    tmp = ""
    
    # text = pd.read_csv(input_path, sep='µ', engine='python', encoding='utf-8')
    # print(text)

    with open(input_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if re.match(pattern, line):
                if tmp:
                    cleaned.append(tmp)
                tmp = line
            else:
                tmp += " " + line

    if tmp:
        cleaned.append(tmp)

    # text.to_csv(output_path, index=False)

    pd.DataFrame(cleaned, columns=["ligne"]).to_csv(output_path, index=False)
