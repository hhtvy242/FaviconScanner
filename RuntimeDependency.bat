@echo off

pip install mmh3
pip install requests
pip install cryptography

echo.
echo Runtime dependencies have been installed.
echo.
echo favicon_scanner_cmd.py grammar:
echo -i or --input: Specify the input file containing URLs (required).
echo -p or --proxy: Specify your local HTTP proxy (optional).
echo -o or --output: Specify the output file path and name (optional; defaults to generating `out_hash.csv` in the current directory).
echo -t or --threads: Specify the number of concurrent threads (optional). Default: 10.
echo.
echo Example grammar:
echo  python favicon_scanner_cmd.py -i urls.txt -o ./output/hash_out.csv -p http://127.0.0.1:10808 -t 50

cmd /k

