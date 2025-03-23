import argparse
import requests
import threading
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor
import random
import traceback
import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# 禁用SSL验证警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36'
]

class Scanner:
    def __init__(self, target_host=None):
        self.target_host = target_host
        self.length_counter = {}
        self.counter_lock = threading.Lock()
        self.threshold = 3
        self.lock = threading.Lock()
        self.BACKUP_EXTENSIONS = [
            'rar', 'tar.gz', '7z', 'zip', 'bak',
            'backup', 'dump', 'sql', 'swp', 'old',
            'temp', 'txt'
        ]

    def generate_backup_names(self, hostname):
        """生成包含多种后缀的备份文件名"""
        parts = hostname.split('.')
        names = set()
        base_names = []

        if len(parts) > 1:
            if parts[0] == 'www':
                main = parts[1]
                suffix = ''.join(parts[2:]) if len(parts) > 2 else ''
                base_names.extend([main, f"{main}{suffix}", "www"])
            else:
                main = parts[0]
                suffix = ''.join(parts[1:])
                base_names.extend([main, f"{main}{suffix}", "www"])
        else:
            base_names.append(hostname)

        for name in base_names:
            for ext in self.BACKUP_EXTENSIONS:
                names.add(f"{name}.{ext}")
                names.add(f"{name}_backup.{ext}")

        return list(names)

    def scan(self, url, user_agents, output_file=None):
        try:
            headers = {'User-Agent': random.choice(user_agents)}
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            status_code = response.status_code
            content_length = len(response.content)

            # 输出带大小的结果
            with self.lock:
                print(f"[{status_code}] {url} [Size: {content_length} bytes]", flush=True)

            with self.counter_lock:
                self.length_counter[content_length] = self.length_counter.get(content_length, 0) + 1
                if self.length_counter[content_length] > self.threshold:
                    return

            if output_file:
                with self.lock:
                    with open(output_file, 'a') as f:
                        f.write(f"[{status_code}] {url} [Size: {content_length} bytes]\n")

        except Exception as e:
            with self.lock:
                print(f"[ERROR] {url} - {str(e)}", flush=True)
                traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(description="多线程目录扫描器")
    parser.add_argument('-u', '--url', help="单个目标URL")
    parser.add_argument('-f', '--file', help="目标文件")
    parser.add_argument('-d', '--dict', required=True, help="字典文件路径")
    parser.add_argument('-t', '--threads', type=int, default=10, help="线程数")
    parser.add_argument('--bak', action='store_true', help="启用备份文件扫描")
    parser.add_argument('-o', '--output', help="输出文件路径")
    args = parser.parse_args()

    # 加载目标列表
    targets = []
    if args.url:
        targets.append(args.url)
    if args.file:
        try:
            with open(args.file, 'r') as f:
                targets.extend([line.strip() for line in f.readlines()])
        except FileNotFoundError:
            print(f"[!] 目标文件不存在: {args.file}")
            exit(1)

    # 目标格式标准化
    valid_targets = []
    for target in targets:
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        parsed = urlparse(target)
        if not parsed.netloc:
            print(f"[!] 无效目标格式: {target}")
            continue
        valid_targets.append(target)
    targets = valid_targets

    if not targets:
        print("[!] 错误：未指定有效扫描目标")
        exit(1)

    # 初始化Scanner实例
    scanners = {}
    for target in targets:
        parsed = urlparse(target)
        host = parsed.hostname.split(':')[0] if parsed.hostname else parsed.netloc.split(':')[0]
        host_key = host.replace("www.", "", 1)
        if host_key not in scanners:
            scanners[host_key] = Scanner(host_key)

    # 加载字典路径
    try:
        with open(args.dict, 'r') as f:
            original_paths = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] 加载字典文件失败: {str(e)}")
        exit(1)

    # 处理备份文件路径
    backup_paths = []
    if args.bak:
        for target in targets:
            parsed = urlparse(target)
            host = parsed.hostname.split(':')[0] if parsed.hostname else parsed.netloc.split(':')[0]
            host_key = host.replace("www.", "", 1)
            scanner = scanners.get(host_key)
            if not scanner:
                continue
            backup_paths.extend(scanner.generate_backup_names(host))

    # 合并路径列表
    paths = list(set(original_paths + backup_paths))
    print(f"[*] 合并后有效路径数: {len(paths)}")

    # 生成扫描任务
    tasks = []
    for target in targets:
        parsed = urlparse(target)
        host = parsed.hostname.split(':')[0] if parsed.hostname else parsed.netloc.split(':')[0]
        host_key = host.replace("www.", "", 1)
        scanner = scanners.get(host_key)
        if not scanner:
            continue

        base_url = f"{parsed.scheme}://{host}/"
        for path in paths:
            clean_path = path.lstrip('/')
            full_url = urljoin(base_url, clean_path)
            tasks.append((scanner, full_url))

    print(f"[*] 生成扫描任务总数: {len(tasks)}")
    if not tasks:
        print("[!] 错误：未生成任何扫描任务")
        exit(1)

    # 执行扫描任务
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        print(f"[*] 启动线程池（线程数: {args.threads}）")
        futures = []
        for scanner, url in tasks:
            futures.append(executor.submit(scanner.scan, url, USER_AGENTS, args.output))
        
        for future in futures:
            future.result()

if __name__ == '__main__':
    main()