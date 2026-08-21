import argparse
import base64
import hashlib
import mmh3
import re
import os
import csv
import urllib3
import requests
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# 忽略 SSL 警告（防止因证书过期导致脚本中断）
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 伪造浏览器请求头，绕过基础反爬
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
}

# 初始化线程锁，确保数据完整写入
thread_lock = threading.Lock()

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="网站图标(Favicon)哈希解析器"
    )
    
    # 必填参数：输入文件
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="包含目标网址的文本文件路径（例如：-i D:/favicon_scanner/urls.txt）",
    )
    
    # 选填参数：输出文件  默认输出至当前路径下自动创建的out_hash.csv中
    parser.add_argument(
        "-o",
        "--output",
        default="out_hash.csv",
        help="指定存放测绘结果的文件路径与名称（例如：-o D:/favicon_scanner/output/hash_out.csv）默认将数据输出至当前路径下自动创建的out_hash.csv中",
    )
    
    # 选填参数：指定代理  默认不使用代理
    parser.add_argument(
        "-p",
        "--proxy",
        default=None,
        help="指定运行脚本时使用的HTTP代理（例如：-p http://127.0.0.1:10808 ）默认不使用代理",
    )
    # 选填参数：指定并发线程数
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=10,
        help="指定并发线程数 (例如: -t 50) 默认：10",
    )
    return parser.parse_args()


def get_real_favicon_url(base_url, proxies):
    """通过主页源码正则匹配图标地址"""
    if not base_url.startswith("http://") and not base_url.startswith("https://"):
        base_url = "http://" + base_url

    try:
        res = requests.get(
            base_url,
            headers=HEADERS,
            proxies=proxies,
            timeout=5,
            verify=False,
            allow_redirects=True,
        )
        if res.status_code == 200:
            match = re.search(
                r'<link[^>]*rel=["\'](?:shortcut )?icon["\'][^>]*href=["\']([^"\']+)["\']',
                res.text,
                re.IGNORECASE,
            )
            if match:
                icon_path = match.group(1)
                if icon_path.startswith("//"):
                    return f"https:{icon_path}"
                elif icon_path.startswith("/"):
                    return f"{res.url.rstrip('/')}/{icon_path.lstrip('/')}"
                elif not icon_path.startswith("http"):
                    return f"{res.url.rstrip('/')}/{icon_path}"
                return icon_path
    except Exception:
        pass
    return f"{base_url.rstrip('/')}/favicon.ico"


def process_url(url, proxies, writer):
    """单个URL的处理逻辑（由子线程调用）"""
    print(f"[+] Detecting Target: {url}")
    favicon_url = get_real_favicon_url(url, proxies)

    try:
        response = requests.get(
            favicon_url,
            headers=HEADERS,
            proxies=proxies,
            timeout=8,
            verify=False,
            allow_redirects=True,
        )

        if response.status_code == 200 and response.content:
            icon_bytes = response.content

            # 计算哈希值
            md5_hash = hashlib.md5(icon_bytes).hexdigest()
            b64_bytes = base64.encodebytes(icon_bytes)
            mmh3_hash = mmh3.hash(b64_bytes)

            # 生成测绘语法
            shodan_query = f"http.favicon.hash:{mmh3_hash}"
            virustotal_query = f'entity:url main_icon_md5:{md5_hash}'
            censys_query_md5 = f'host.services.endpoints.http.favicons.hash_md5:"{md5_hash}"'
            censys_query_mmh3 = f'host.services.endpoints.http.favicons.hash_shodan:"{mmh3_hash}"'
            
            # 拼接搜索链接
            shodan_search = "https://www.shodan.io/search?query="
            virustotal_search = "https://www.virustotal.com/gui/search/entity:url%20main_icon_md5:"
            censys_search_md5 = "https://platform.censys.io/search?q=host.services.endpoints.http.favicons.hash_md5%3A%22"
            censys_search_mmh3 = "https://platform.censys.io/search?q=host.services.endpoints.http.favicons.hash_shodan%3A%22"
            
            shodan_url = f"{shodan_search}{shodan_query}"
            virustotal_url = f"{virustotal_search}{md5_hash}"
            censys_url_md5 = f"{censys_search_md5}{md5_hash}%22"
            censys_url_mmh3 = f"{censys_search_mmh3}{mmh3_hash}%22"
            
            print(f"{'='*40}\nTarget {url} Hash value successfully retrieved")
            print(f"   ICON link: {favicon_url}")
            print(f"   MMH3 hash: {mmh3_hash}")
            print(f"   MD5  hash: {md5_hash}")
            print(f"   Shodan Search link: {shodan_url}")
            print(f"   Virustotal Search link: {virustotal_url}")
            print(f"   Censys MD5 Search link: {censys_url_md5}")
            print(f"   Censys MMH3 Search link: {censys_url_mmh3}")
            
            row_data = [f"""{"="*8}Target {url} Analysis results{"="*8}
ICON link: {favicon_url}
MMH3 hash: {mmh3_hash}
MD5  hash: {md5_hash}
Shodan Search query: 
{shodan_query}
Virustotal Search query: 
{virustotal_query}
Censys MD5 Search query: 
{censys_query_md5}
Censys MMH3 Search query:
{censys_query_mmh3}
Shodan Search link: 
{shodan_url}
Virustotal Search link:
{virustotal_url}
Censys MD5 Search link: 
{censys_url_md5}
Censys MMH3 Search link:
{censys_url_mmh3}
{"="*48}"""]

        else:
            print(f"Failed to download website icon. Status code: {response.status_code}")
            row_data = [f"""{"-"*8}Target {url} Failed to download website icon.{"-"*8}\nFavicon link: {favicon_url}\Status code: {response.status_code}\n"""]
                    
    except requests.exceptions.RequestException as e:
        print(f"Network error: {e}")
        row_data = [f"""{"-"*4}Target {url} Network exception occurred while parsing the hash value.{"-"*4}\nFavicon link: {favicon_url}\nError message:\n{str(e)}\n{"-"*92}"""]
    except Exception as e:
        print(f"unexpected error occurred: {e}")
        row_data = [f"""{"-"*8}Target {url} Parsing exception {"-"*8}\nFavicon link: {favicon_url}\nError message:\n{str(e)}\n{"-"*92}"""]

    # 使用线程锁，确保同一时间只有一个线程写入文件，防止数据错乱
    with thread_lock:
        writer.writerow(row_data)
    counter += 1

def main():
    args = parse_args()

    # 1. 配置代理
    proxies = None
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}
        print(f"Proxy enabled：{args.proxy}")
    else:
        print("Proxy not enabled; using local connection.")
        
    # 2. 读取目标网址
    if not os.path.exists(args.input):
        print(f"error：Input file not found {args.input}")
        sys.exit(1)

    with open(args.input, "r", encoding="utf-8") as f:
        # 去除每一行的空格和换行符并过滤空行
        targets = [line.strip() for line in f if line.strip()]
    
    print(f"Successfully loaded {len(targets)} target URLs. Current thread concurrency count: {args.threads}\nStart scanning...")
    
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_file = Path(args.output)
    out_file.touch(exist_ok=True)
    
    # 3. 打开导出文件
    with open(args.output, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        # 4. 使用线程池并发请求
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            # 提交所有任务到线程池
            futures = [
                executor.submit(process_url, url, proxies, writer) for url in targets
            ]
            
            for future in as_completed(futures):
                pass

    print(f"""{"="*40}\nAnalysis complete. Results have been saved to: {args.output}""")


if __name__ == "__main__":
    main()
