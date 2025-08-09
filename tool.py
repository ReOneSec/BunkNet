import requests
import threading
import time
import json
import hashlib
import os
import random
import sys
import argparse
import queue
import datetime
from eth_keys import keys
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

# --- Constants ---
WALLET_FILE = "test_wallets.json"
CONFIG_FILE = "config.json"
FAILED_TXS_FILE = "failed_txs.json"

# Initialize rich console
console = Console()

# =============================================================================
# --- CORE LOGIC ---
# =============================================================================

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

def generate_wallets(count):
    console.print(f"Generating {count} new wallets...")
    wallets = []
    for _ in range(count):
        private_key_bytes = os.urandom(32)
        pk = keys.PrivateKey(private_key_bytes)
        wallets.append({"private_key": pk.to_hex(), "address": pk.public_key.to_checksum_address()})

    with open(WALLET_FILE, 'w') as f:
        json.dump(wallets, f, indent=4)
    
    console.print(f"[bold green]✅ Success![/bold green] Generated and saved {count} wallets to [cyan]{WALLET_FILE}[/cyan].")
    console.print("\n[bold yellow]Next Step:[/bold yellow] Use the 'Fund Wallets' option from the main menu.")

def fund_wallets(url, admin_key, amount, concurrency):
    try:
        with open(WALLET_FILE, 'r') as f:
            wallets_to_fund = json.load(f)
        addresses = [w['address'] for w in wallets_to_fund]
        console.print(f"Found {len(addresses)} wallets in [cyan]{WALLET_FILE}[/cyan] to fund.")
    except FileNotFoundError:
        console.print(f"❌ [bold red]ERROR:[/bold red] '{WALLET_FILE}' not found. Please generate wallets first.")
        return

    stats = {'success': 0, 'failure': 0}
    lock = threading.Lock()
    task_queue = [addr for addr in addresses]

    def worker():
        headers = {'X-Admin-Key': admin_key}
        while True:
            with lock:
                if not task_queue: break
                address = task_queue.pop(0)
            
            payload = {'recipient': address, 'amount': amount}
            try:
                response = requests.post(f"{url}/admin/mint", headers=headers, json=payload, timeout=15)
                with lock:
                    if response.status_code == 201:
                        stats['success'] += 1
                    else:
                        stats['failure'] += 1
                progress.update(task_id, advance=1)
            except Exception:
                with lock:
                    stats['failure'] += 1
                progress.update(task_id, advance=1)
    
    with Progress(SpinnerColumn(), *Progress.get_default_columns(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task_id = progress.add_task(f"[cyan]Funding {len(addresses)} wallets...", total=len(addresses))
        threads = [threading.Thread(target=worker) for _ in range(concurrency)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    console.print("\n--- Funding Complete ---")
    summary_table = Table(title="Funding Summary")
    summary_table.add_column("Status", style="cyan")
    summary_table.add_column("Count", style="magenta")
    summary_table.add_row("✅ Successfully Funded", str(stats['success']))
    summary_table.add_row("❌ Failed to Fund", str(stats['failure']))
    console.print(summary_table)

def run_load_test(url, total_txs, concurrency, tps_throttle):
    try:
        with open(WALLET_FILE, 'r') as f:
            wallets_data = json.load(f)
        wallets = {w['address']: {"pk": keys.PrivateKey(bytes.fromhex(w['private_key'][2:])), "nonce": 0, "lock": threading.Lock()} for w in wallets_data}
        addresses = list(wallets.keys())
        console.print(f"Loaded {len(wallets)} wallets for the test.")
    except FileNotFoundError:
        console.print(f"❌ [bold red]ERROR:[/bold red] Wallet files not found. Please generate and fund wallets first.")
        return
        
    for address in wallets:
        try:
            res = requests.get(f"{url}/address/{address}", timeout=5)
            if res.ok:
                wallets[address]["nonce"] = res.json().get('nonce', 0)
        except Exception:
            pass
    
    stats = {'success': 0, 'failure': 0, 'failed_txs': [], 'start_time': time.time()}
    lock = threading.Lock()
    task_queue = queue.Queue(maxsize=concurrency * 2)
    shutdown_event = threading.Event()

    def producer():
        for _ in range(total_txs):
            if shutdown_event.is_set(): break
            sender_addr, recipient_addr = random.sample(addresses, 2)
            task_queue.put((sender_addr, recipient_addr))
            if tps_throttle > 0:
                time.sleep(1.0 / tps_throttle)
        for _ in range(concurrency):
            task_queue.put(None)
    
    def test_worker():
        while not shutdown_event.is_set():
            task = task_queue.get()
            if task is None: break
            
            sender_addr, recipient_addr = task
            wallet = wallets[sender_addr]
            
            with wallet['lock']:
                nonce = wallet['nonce']
                wallet['nonce'] += 1
            
            payload, error_msg = None, ""
            try:
                tx_data = {'sender': sender_addr, 'recipient': recipient_addr, 'amount': '0.01', 'fee': '0.01', 'nonce': nonce}
                tx_data_str = json.dumps(tx_data, sort_keys=True, separators=(',', ':')).encode()
                msg_hash = hashlib.sha256(tx_data_str).digest()
                sig_obj = wallet['pk'].sign_msg_hash(msg_hash)
                payload = {'public_key': wallet['pk'].public_key.to_bytes().hex(), 'signature': sig_obj.to_bytes().hex(), **tx_data}
                
                response = requests.post(f"{url}/new_transaction", json=payload, timeout=10)
                
                if response.status_code == 201:
                    with lock: stats['success'] += 1
                else:
                    error_msg = response.text
                    with lock:
                        stats['failure'] += 1
                        stats['failed_txs'].append({"payload": payload, "error": error_msg})
            except Exception as e:
                error_msg = str(e)
                with lock:
                    stats['failure'] += 1
                    if payload:
                        stats['failed_txs'].append({"payload": payload, "error": error_msg})
            
            progress.update(task_id, advance=1)
    
    with Progress(SpinnerColumn(), BarColumn(), "[progress.percentage]{task.percentage:>3.0f}%", TextColumn("{task.completed} of {task.total} Txns"), TimeElapsedColumn(), transient=True) as progress:
        task_id = progress.add_task(f"[cyan]Sending Transactions...", total=total_txs)
        
        producer_thread = threading.Thread(target=producer)
        producer_thread.start()

        threads = [threading.Thread(target=test_worker) for _ in range(concurrency)]
        for t in threads:
            t.start()
        
        producer_thread.join()
        for t in threads:
            t.join()

    duration = time.time() - stats['start_time']
    tps = stats['success'] / duration if duration > 0 else 0
    
    console.print("\n--- Load Test Complete ---")
    summary_table = Table(title="Load Test Summary")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="magenta")
    summary_table.add_row("✅ Successful Transactions", str(stats['success']))
    summary_table.add_row("❌ Failed Transactions", str(stats['failure']))
    summary_table.add_row("⏱️ Total Duration", f"{duration:.2f} seconds")
    summary_table.add_row("🚀 Average TPS", f"{tps:.2f}")
    console.print(summary_table)
    
    if stats['failed_txs']:
        console.print(f"\n[bold yellow]Saving {len(stats['failed_txs'])} failed transactions to [cyan]{FAILED_TXS_FILE}[/cyan] for debugging.[/bold yellow]")
        with open(FAILED_TXS_FILE, 'w') as f:
            json.dump(stats['failed_txs'], f, indent=4)

def print_main_menu():
    console.print(Panel.fit(
        "[bold cyan]BunkNet Command-Line Interface (CLI)[/bold cyan]\n"
        "Select an action to perform.",
        title="Main Menu",
        border_style="green"
    ))
    console.print("  [1] Generate Wallets")
    console.print("  [2] Fund Wallets")
    console.print("  [3] Run Load Test")
    console.print("  [4] Exit")

# =============================================================================
# --- MAIN INTERACTIVE LOOP ---
# =============================================================================
if __name__ == "__main__":
    config = load_config()

    while True:
        print_main_menu()
        choice = Prompt.ask("\nEnter your choice", choices=["1", "2", "3", "4"], default="4")

        if choice == '1':
            count_str = Prompt.ask("How many wallets to generate?", default="1000")
            if count_str.isdigit():
                generate_wallets(int(count_str))
            else:
                console.print("[bold red]Invalid input. Please enter a whole number.[/bold red]")
        
        elif choice == '2':
            config['url'] = Prompt.ask("Enter your BunkNet API URL", default=config.get('url', 'http://127.0.0.1:5000'))
            config['admin_key'] = Prompt.ask("Enter your Admin Key", default=config.get('admin_key'), password=True)
            amount_str = Prompt.ask("Amount to mint per wallet?", default="100.0")
            concurrency_str = Prompt.ask("How many concurrent funding threads?", default="20")
            
            try:
                save_config(config)
                fund_wallets(config['url'], config['admin_key'], float(amount_str), int(concurrency_str))
            except ValueError:
                console.print("[bold red]Invalid amount or concurrency. Please enter valid numbers.[/bold red]")

        elif choice == '3':
            config['url'] = Prompt.ask("Enter your BunkNet API URL", default=config.get('url', 'http://127.0.0.1:5000'))
            total_txs_str = Prompt.ask("Total transactions to send?", default="10000")
            concurrency_str = Prompt.ask("How many concurrent test threads?", default="100")
            tps_throttle_str = Prompt.ask("Target TPS (0 for unlimited)?", default="0")
            
            try:
                save_config(config)
                if Confirm.ask("\nThis will start the load test. Are you sure?"):
                    run_load_test(config['url'], int(total_txs_str), int(concurrency_str), int(tps_throttle_str))
            except ValueError:
                console.print("[bold red]Invalid input. Please enter valid whole numbers.[/bold red]")

        elif choice == '4':
            console.print("[bold]Exiting. Goodbye![/bold]")
            break
        
        Prompt.ask("\n[italic]Press Enter to return to the main menu...[/italic]")
      
