import argparse
from pathlib import Path

from modules.log_analyzer import LogAnalyzer


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('log_file_path', type=str, help='Log file path')
    args = parser.parse_args()
    input_path = Path(args.log_file_path)

    if not input_path.is_absolute():
        input_path = Path.cwd() / input_path

    file_exists = True
    if not input_path.exists() or not input_path.is_file():
        print(f'The file {input_path} does not exist!')
        file_exists = False

    if file_exists:
        log_analyzer = LogAnalyzer(input_path)
        log_analyzer.analyze()