import argparse
import requests
import threading
import time
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor
import random
import traceback
import urllib3
from queue import Queue
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# 禁用SSL警告
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
        """流式生成备份文件名"""
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

def path_generator(dict_path, targets, bak_enabled):
    """流式路径生成器"""
    # 生成字典文件路径
    try:
        with open(dict_path, 'r') as f:
            for line in f:
                path = line.strip()
                if path:
                    yield path
    except FileNotFoundError:
        print(f"[!] 字典文件不存在: {dict_path}")
        exit(1)

    # 生成备份路径
    if bak_enabled:
        for target in targets:
            parsed = urlparse(target)
            host = parsed.hostname.split(':')[0] if parsed.hostname else parsed.netloc.split(':')[0]
            scanner = Scanner(host)
            for name in scanner.generate_backup_names(host):
                yield name

def producer(task_queue, dict_path, targets, bak_enabled, max_queued=1000):
    """生产者线程"""
    for target in targets:
        # 标准化URL
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        parsed = urlparse(target)
        host = parsed.hostname.split(':')[0] if parsed.hostname else parsed.netloc.split(':')[0]
        scanner = Scanner(host)
        base_url = f"{parsed.scheme}://{host}/"

        # 生成任务
        for path in path_generator(dict_path, [target], bak_enabled):
            # 队列控制
            while task_queue.qsize() > max_queued:
                time.sleep(0.1)
            
            full_url = urljoin(base_url, path.lstrip('/'))
            task_queue.put( (scanner, full_url) )
    
    # 发送结束信号
    task_queue.put(None)

def consumer(task_queue, output_file):
    """消费者线程"""
    while True:
        task = task_queue.get()
        if task is None:
            task_queue.put(None)  # 传递结束信号
            break
        
        scanner, url = task
        scanner.scan(url, USER_AGENTS, output_file)
        task_queue.task_done()

def main():
    parser = argparse.ArgumentParser(description="内存优化的多线程目录扫描器")
    parser.add_argument('-u', '--url', help="单个目标URL")
    parser.add_argument('-f', '--file', help="目标文件")
    parser.add_argument('-d', '--dict', required=True, help="字典文件路径")
    parser.add_argument('-t', '--threads', type=int, default=10, help="线程数")
    parser.add_argument('--bak', action='store_true', help="启用备份文件扫描")
    parser.add_argument('-o', '--output', help="输出文件路径")
    args = parser.parse_args()

    # 加载目标
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

    # 过滤无效目标
    valid_targets = []
    for target in targets:
        parsed = urlparse(target)
        if not parsed.netloc:
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

    # 创建任务队列
    task_queue = Queue(maxsize=10)

    # 启动生产者线程
    producer_thread = threading.Thread(
        target=producer,
        args=(task_queue, args.dict, targets, args.bak)
    )
    producer_thread.start()

    # 启动消费者线程池
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        # 提交消费者任务
        futures = [executor.submit(consumer, task_queue, args.output) 
                  for _ in range(args.threads)]
        
        # 等待生产者完成
        producer_thread.join()
        task_queue.put(None)  # 结束信号
        
        # 等待所有任务完成
        task_queue.join()
        for future in futures:
            future.cancel()

if __name__ == '__main__':
    main()
