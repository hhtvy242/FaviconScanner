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

# 指定目标网址
targets = ["example.com", ""]

"""
# 代理配置 本地回环ip后面填写代理端口(v2rayN的代理端口通常是10808或10809，可在软件底部状态栏察看实际端口) 不使用代理则设置为 PROXIES = None 
PROXIES = {
    "http": "http://127.0.0.1:10808",
    "https": "http://127.0.0.1:10808",
}
"""

PROXIES = None

# 伪造浏览器请求头，绕过基础反爬
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
}

THREADS = 10
# 初始化线程锁，确保数据完整写入
thread_lock = threading.Lock()

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
    print(f"[+] 正在探测目标: {url}")
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
            
            print(f"{'='*40}\n目标 {url} 的哈希值获取成功")
            print(f"   ICON 链接: {favicon_url}")
            print(f"   MMH3 哈希值: {mmh3_hash}")
            print(f"   MD5  哈希值: {md5_hash}")
            print(f"   Shodan 搜索链接: {shodan_url}")
            print(f"   Virustotal 搜索链接: {virustotal_url}")
            print(f"   Censys MD5搜索链接: {censys_url_md5}")
            print(f"   Censys MMH3搜索链接: {censys_url_mmh3}")
            
            row_data = [f"""{"="*8}目标{url} 的解析结果{"="*8}
ICON 链接: {favicon_url}
MMH3 哈希值: {mmh3_hash}
MD5  哈希值: {md5_hash}
Shodan搜索语法: 
{shodan_query}
Virustotal 搜索语法: 
{virustotal_query}
Censys MD5搜索语法: 
{censys_query_md5}
Censys MMH3搜索语法:
{censys_query_mmh3}
Shodan搜索链接: 
{shodan_url}
Virustotal 搜索链接:
{virustotal_url}
Censys MD5搜索链接: 
{censys_url_md5}
Censys MMH3搜索链接:
{censys_url_mmh3}
{"="*48}"""]

        else:
            print(f"下载失败，网页状态码: {response.status_code}")
            row_data = [f"""{"-"*8}目标 {url} 的网站图标下载失败{"-"*8}\n图标链接: {favicon_url}\n状态码: {response.status_code}\n"""]
                    
    except requests.exceptions.RequestException as e:
        print(f" 网络请求异常: {e}")
        row_data = [f"""{"-"*8}解析目标 {url} 的哈希值时出现网络异常{"-"*8}\n图标链接: {favicon_url}\n报错信息:\n{str(e)}\n{"-"*92}"""]
    except Exception as e:
        print(f"出现未知异常: {e}")
        row_data = [f"""{"-"*8}解析目标 {url} 时出现异常 {"-"*8}\n图标链接: {favicon_url}\n报错信息:\n{str(e)}\n{"-"*92}"""]

    # 使用线程锁，确保同一时间只有一个线程写入文件，防止数据错乱
    with thread_lock:
        writer.writerow(row_data)

def main():

    # 1. 配置代理
    proxies = PROXIES
        
    # 2. 设置导出文件
    out_file = r"E:\BugBounty\pythonscript\ip_plumb\favicon_scanner\output\out_hash.csv"
    out_path = Path(out_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_file = Path(out_file)
    out_file.touch(exist_ok=True)
    
    # 3. 打开导出文件
    with open(out_file, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        # 4. 使用线程池并发请求
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            # 提交所有任务到线程池
            futures = [
                executor.submit(process_url, url, proxies, writer) for url in targets
            ]
            
            for future in as_completed(futures):
                pass

    print(f"""{"="*40}\n解析结束 结果已保存至: {out_file}""")


if __name__ == "__main__":
    main()
