import regex as re
import requests
import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.progress import (
    Progress,
    BarColumn,
    TimeRemainingColumn,
    TextColumn,
    TimeElapsedColumn,
)
from urllib.parse import urlparse
from rich.panel import Panel
from rich.table import Table

console = Console()


# ================== Load Secret Regex Patterns from JSON ==================
def load_patterns(json_file):
    with open(json_file, "r") as f:
        patterns = json.load(f)
    return patterns


# ================== Banner ==================
def print_banner():
    banner = """
███████╗███████╗ ██████╗██████╗ ███████╗████████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝╚══██╔══╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
███████╗█████╗  ██║     ██████╔╝█████╗     ██║       ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
╚════██║██╔══╝  ██║     ██╔══██╗██╔══╝     ██║       ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
███████║███████╗╚██████╗██║  ██║███████╗   ██║       ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝       ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
    """
    console.print(
        Panel.fit(
            banner,
            title="[bold green]Secret Hunter[/bold green]",
            border_style="red",
            style="blue",
        )
    )


# ================== Worker Function ==================
def check_url(url, timeout, patterns):
    secrets_found = []
    try:
        r = requests.get(url, timeout=timeout)
        if r.ok:
            for pattern in patterns:
                name = pattern.get("name")
                regex = pattern.get("regex")
                confidence = pattern.get("confidence", "low")
                matches = regex.findall(r.text)
                if matches:
                    secrets_found.append((name, matches, confidence))
    except Exception:
        return url, []
    return url, secrets_found


def uniq_urls(urls):
    result = []
    js_extensions = (".json", ".js")
    for url in urls:
        url = url.strip()
        parsed_url = urlparse(url)
        clean_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        if parsed_url.path.lower().endswith(js_extensions):
            result.append(clean_url)
    return result


def compile_pattern(pat):
    regex = pat.get("regex")
    name = pat.get("name", "unknown")
    if regex:
        try:
            pat["regex"] = re.compile(regex)
        except re.error as e:
            console.print(f"[❌ ERROR] {name}: {regex}\n   └─ {e}")
    return pat


def check_regexs(patterns, threads=10):
    compiled_patterns = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(compile_pattern, pat) for pat in patterns]
        for future in as_completed(futures):
            try:
                compiled_patterns.append(future.result())
            except Exception as e:
                console.print(f"[red]Regex compile failed:[/red] {e}")
    return compiled_patterns


# ================== Main ==================
def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="Secret Hunter - Find hardcoded secrets in JS"
    )
    parser.add_argument("-i", "--file", required=True, help="Input file with list of URLs")
    parser.add_argument(
        "-p",
        "--patterns",
        required=True,
        default="main_patterns.json",
        help="JSON file with regex patterns for secrets",
    )
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads (default=50)")
    parser.add_argument("--timeout", type=int, default=6, help="Request timeout in seconds (default=20)")
    args = parser.parse_args()

    with open(args.file, "r") as f:
        urls = [line.strip() for line in f if line.strip()]
    urls = uniq_urls(urls)

    patterns = load_patterns(args.patterns)
    patterns = check_regexs(patterns, threads=args.threads)
    results = []

    with Progress(
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=None, style="cyan"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("{task.completed}/{task.total}", style="magenta"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("🔎 Scanning URLs...", total=len(urls))
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_url = {executor.submit(check_url, url, args.timeout, patterns): url for url in urls}
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                progress.update(task, advance=1, url=url)
                try:
                    url, secrets = future.result()
                    if secrets:
                        results.append((url, secrets))
                        console.print(
                            Panel.fit(
                                f"[bold red]⚠️ Secrets found in [cyan]{url}[/cyan][/bold red]",
                                border_style="red",
                            )
                        )
                except Exception:
                    pass

    console.print("\n[bold red]=== Scan Results ===[/bold red]")
    if not results:
        console.print(Panel.fit("[green]✅ No secrets found[/green]", border_style="green"))
    else:
        for url, secrets in results:
            table = Table(
                title=f"[cyan]🔑 Secrets in [bold]{url}[/bold][/cyan]",
                expand=True,
                show_lines=True,
                header_style="bold magenta",
            )
            table.add_column("Secret Type", style="white", no_wrap=True)
            table.add_column("Matches", style="green")
            table.add_column("Confidence", style="bold")

            for name, matches, confidence in secrets:
                clean_matches = [m if isinstance(m, str) else "".join(m) for m in set(matches)]

                if confidence.lower() == "high":
                    conf_display = "🔥 [bold red]HIGH[/bold red]"
                elif confidence.lower() == "medium":
                    conf_display = "⚠️ [bold yellow]MEDIUM[/bold yellow]"
                else:
                    conf_display = "✅ [bold green]LOW[/bold green]"

                table.add_row(f"[red]{name}[/red]", "\n".join(clean_matches), conf_display)

            console.print(table)


if __name__ == "__main__":
    main()
