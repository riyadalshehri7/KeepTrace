#!/usr/bin/env python3
"""KeepTrace Framework - Linux-first digital forensics workspace MVP."""
from __future__ import annotations
import csv, hashlib, json, os, shutil, subprocess, sys, textwrap, urllib.request, zipfile, tempfile
import shlex
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CATALOG = ROOT / "official_tools" / "catalog.json"
USER_ROOT = Path.home() / ".keeptrace"
CUSTOM_DIR = USER_ROOT / "custom_tools"
CASES_DIR = USER_ROOT / "cases"
CASES_INDEX = CASES_DIR / "cases.json"
LOG_DIR = USER_ROOT / "logs"
VENV_DIR = USER_ROOT / "venvs"

BANNER = r"""
                         ●
                         │
                    Evidence
                         │
                         │
        ●───────────────◎───────────────●
     Network                           Disk
                         │
                         │
                       Memory
                         ●
                        ╱ ╲
                       ●   ●

                      KEEPTRACE

              KEEPTRACE FRAMEWORK
       Digital Forensics & Cyber Defense
             Created by Riyad Alshehri
       Keep Learning. Keep Investigating.
"""

def now(): return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
def safe_name(value):
    value = value.strip().lower().replace(" ", "-")
    return "".join(c for c in value if c.isalnum() or c in "-_")[:80] or "case"
def read_json(path, default):
    try: return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError): return default
def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""): h.update(block)
    return h.hexdigest()
def log_event(kind, detail):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with (LOG_DIR / "keeptrace.log").open("a") as f: f.write(f"{now()} | {kind} | {detail}\n")
def prompt_choice(label, options):
    print(f"\n{label}")
    for i, item in enumerate(options, 1): print(f"{i}. {item}")
    print("0. Back")
    return input("Select: ").strip()
def confirm(message): return input(f"{message} [y/N]: ").strip().lower() == "y"

def catalog(): return read_json(CATALOG, [])
def all_tools():
    official = [{**x, "source": "official"} for x in catalog()]
    custom = []
    for p in CUSTOM_DIR.glob("*.json"):
        item = read_json(p, {})
        if item.get("name"): custom.append({**item, "source": "custom", "definition": str(p)})
    return official + custom

def command_exists(tool):
    checks = tool.get("check_commands", [tool.get("check_command", tool.get("command", ""))])
    check = next((x for x in checks if shutil.which(x) or Path(x).expanduser().exists()), checks[0])
    if tool.get("install_method") == "pip_venv":
        path = VENV_DIR / safe_name(tool["name"]) / "bin" / tool.get("venv_command", check)
        return path.exists() and os.access(path, os.X_OK)
    return bool(shutil.which(check) or Path(check).expanduser().exists())

def resolved_command(tool):
    if tool.get("install_method") == "pip_venv":
        return str(VENV_DIR / safe_name(tool["name"]) / "bin" / tool.get("venv_command", tool.get("command")))
    commands = tool.get("launch_commands", [tool.get("launch_command", tool.get("command"))])
    return next((x for x in commands if shutil.which(x) or Path(x).expanduser().exists()), commands[0])

def terminal_command():
    for name in ("qterminal", "xfce4-terminal", "mate-terminal", "gnome-terminal", "konsole", "lxterminal", "xterm"):
        path = shutil.which(name)
        if path: return path, name
    return None, None

def safe_extract_zip(archive, destination):
    destination = destination.resolve()
    with zipfile.ZipFile(archive) as z:
        for member in z.infolist():
            target = (destination / member.filename).resolve()
            if target != destination and destination not in target.parents:
                raise ValueError("archive contains an unsafe path")
        z.extractall(destination)

def verify_integrity():
    manifest = ROOT / "security" / "manifest.json"
    if not manifest.exists():
        print("[!] Development mode: integrity manifest not initialized.")
        return True
    data = read_json(manifest, {})
    failures = []
    for rel, expected in data.get("files", {}).items():
        path = ROOT / rel
        if not path.exists() or sha256(path) != expected: failures.append(rel)
    if failures:
        print("[!] Framework integrity check failed.")
        for f in failures: print(f"    - {f}")
        print("[!] Safe Mode: official tool actions are disabled.")
        return False
    if data.get("signature") == "ed25519" and (ROOT / "security/manifest.sig").exists() and (ROOT / "security/keeptrace-release-public.pem").exists():
        result = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(ROOT / "security/keeptrace-release-public.pem"), "-sigfile", str(ROOT / "security/manifest.sig"), "-in", str(manifest), "-rawin"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode != 0:
            print("[!] Manifest signature verification failed.")
            print("[!] Safe Mode: official tool actions are disabled.")
            return False
        print("[✓] Manifest signature verified.")
    print("[✓] Framework integrity verified.")
    return True

def tool_status(tool): return "Installed" if command_exists(tool) else "Missing"
def install_tool(tool):
    if tool.get("source") == "custom":
        print("[!] Custom tools are never installed automatically. Add the tool locally first.")
        return
    if command_exists(tool): print(f"[✓] {tool['name']} is already installed."); return
    method = tool.get("install_method")
    package = tool.get("package")
    if method == "apt": cmd = ["sudo", "apt-get", "install", "-y", package]
    elif method == "pip_venv":
        venv = VENV_DIR / safe_name(tool["name"])
        print("[+] Using isolated Python environment:", venv)
        if not confirm("Create the isolated environment and install this tool?"): return
        result = subprocess.run([sys.executable, "-m", "venv", str(venv)])
        if result.returncode != 0: print("[!] Could not create the isolated environment."); return
        cmd = [str(venv / "bin" / "pip"), "install", package]
    elif method == "pip": cmd = [sys.executable, "-m", "pip", "install", package, "--break-system-packages"]
    else:
        print("[!] No approved installer is defined for this official tool."); return
    print("Command:", " ".join(cmd))
    if not confirm("Run this installation command?"): return
    result = subprocess.run(cmd)
    log_event("TOOL_INSTALL", tool["name"])
    print("[✓] Installation completed." if result.returncode == 0 else "[!] Installation failed.")

def run_context():
    c = prompt_choice("RUN TOOL", ["Create New Case and Run", "Run in Existing Open Case", "Run Standalone"])
    if c == "1": return new_case()
    if c == "2":
        cases = [p for p in case_dirs() if read_json(p / "case.json", {}).get("status") == "Open"]
        x = prompt_choice("OPEN CASES", [p.name for p in cases])
        return None if x == "0" else cases[int(x)-1]
    return None

def choose_evidence(folder):
    if not folder: return None
    evid = read_json(folder / "case.json", {}).get("evidence", [])
    x = prompt_choice("SELECT EVIDENCE", [f"{e['id']} - {e['name']}" for e in evid])
    return None if x == "0" else evid[int(x)-1]

def tool_arguments(tool, folder):
    if not folder: return shlex.split(input("Arguments (Enter for no arguments): ").strip()), None
    name = tool["name"].lower()
    if "tshark" not in name:
        return shlex.split(input("Advanced arguments (Enter for no arguments): ").strip()), None
    mode = prompt_choice("TSHARK FEATURES", ["Live Capture", "Read PCAP/PCAPNG File", "Protocol Hierarchy", "Conversations", "Export Selected Fields", "Advanced Arguments"])
    if mode == "0": return None, None
    if mode == "1":
        interface = input("Interface (Enter for default): ").strip(); count = input("Packet limit (optional): ").strip()
        args = (["-i", interface] if interface else []) + (["-c", count] if count else [])
        return args, None
    if mode == "6": return shlex.split(input("Advanced arguments: ").strip()), None
    evidence = choose_evidence(folder)
    if not evidence: return None, None
    path = str((folder / evidence["stored_path"]).resolve()); count = input("Packet limit (optional): ").strip()
    if mode == "2": args = ["-r", path] + (["-c", count] if count else [])
    elif mode == "3": args = ["-r", path, "-q", "-z", "io,phs"]
    elif mode == "4": args = ["-r", path, "-q", "-z", "conv,tcp"]
    elif mode == "5":
        fields = input("Fields (example: ip.src,ip.dst,tcp.port): ").strip()
        args = ["-r", path, "-T", "fields"] + sum((["-e", f] for f in fields.split(",") if f), [])
    return args, evidence["id"]

def launch_tool(tool):
    if tool.get("source") == "custom":
        print("[!] Warning: this custom tool is not verified by KeepTrace.")
        print("Path/command:", tool.get("launch_command", tool.get("command")))
        if not confirm("Run this custom tool?"): return
    if not command_exists(tool):
        print(f"[!] {tool['name']} is not installed.")
        if confirm("Install and launch it?"):
            install_tool(tool)
        if not command_exists(tool): return
    folder = run_context()
    cmd = resolved_command(tool)
    args, evidence_id = tool_arguments(tool, folder)
    if args is None: return
    command = [cmd] + args
    print("[+] Running:", " ".join(shlex.quote(x) for x in command))
    log_event("TOOL_LAUNCH", tool["name"])
    output_file = None
    analysis_id = None
    if folder:
        meta = read_json(folder / "case.json", {})
        analysis_id = f"A-{len(meta.get('analyses', []))+1:04d}"
        output_file = folder / "tool_output" / f"{analysis_id}_{safe_name(tool['name'])}.txt"
        analysis = {"analysis_id": analysis_id, "tool": tool["name"], "evidence_id": evidence_id, "command": command, "started_at": now(), "status": "running", "output_file": str(output_file.relative_to(folder))}
        meta.setdefault("analyses", []).append(analysis); write_json(folder / "case.json", meta); append_activity(folder, "TOOL_STARTED", f"{analysis_id} {tool['name']}")
    term, term_name = terminal_command()
    try:
        if term:
            shell_line = " ".join(shlex.quote(x) for x in command)
            if output_file:
                shell_line = "set -o pipefail; " + shell_line + " 2>&1 | tee " + shlex.quote(str(output_file))
                shell_line += f"; rc=$?; {shlex.quote(sys.executable)} {shlex.quote(str(ROOT / 'keeptrace.py'))} --mark-analysis {shlex.quote(str(folder))} {shlex.quote(analysis_id)} $rc"
            if term_name == "qterminal": subprocess.Popen([term, "--execute", "bash", "-lc", f"{shell_line}; printf '\\n[KeepTrace] Tool finished. Press Enter to close...'; read"])
            elif term_name == "xfce4-terminal": subprocess.Popen([term, "--title", f"KeepTrace - {tool['name']}", "--", "bash", "-lc", f"{shell_line}; printf '\\n[KeepTrace] Tool finished. Press Enter to close...'; read"])
            elif term_name == "gnome-terminal": subprocess.Popen([term, "--title", f"KeepTrace - {tool['name']}", "--", "bash", "-lc", f"{shell_line}; printf '\\n[KeepTrace] Tool finished. Press Enter to close...'; read"])
            elif term_name == "konsole": subprocess.Popen([term, "--hold", "-e", "bash", "-lc", shell_line])
            else: subprocess.Popen([term, "-hold", "-e", shell_line])
            print(f"[✓] Opened a new terminal for {tool['name']}.")
        else:
            print("[!] No supported terminal emulator found; running in this terminal.")
            if output_file:
                with output_file.open("w") as out: subprocess.run(command, stdout=out, stderr=subprocess.STDOUT)
            else: subprocess.run(command)
    except OSError as e: print("[!] Launch failed:", e)

def show_tool_help(tool):
    if not command_exists(tool):
        print(f"[!] {tool['name']} is not installed.")
        return
    command = [resolved_command(tool)] + tool.get("default_args", ["--help"])
    print("[+] Running help:", " ".join(shlex.quote(x) for x in command))
    subprocess.run(command)

def tool_menu(tool, integrity_ok):
    tool_info(tool)
    while True:
        x = prompt_choice("TOOL ACTIONS", ["Launch Tool", "Show Help", "Show Information"])
        if x == "0": return
        if x == "1":
            if integrity_ok: launch_tool(tool)
            else: print("[!] Safe Mode: official tool actions are disabled.")
        elif x == "2":
            if integrity_ok: show_tool_help(tool)
            else: print("[!] Safe Mode: official tool actions are disabled.")
        elif x == "3": tool_info(tool)

def tool_info(tool):
    print(f"\nName: {tool['name']}\nCategory: {tool.get('category','-')}\nDescription: {tool.get('description','-')}\nSource: {tool.get('source')}\nStatus: {tool_status(tool)}\nCommand: {tool.get('command','-')}\nInstall method: {tool.get('install_method','local/custom')}")

def tool_manager(integrity_ok):
    while True:
        c = prompt_choice("TOOL MANAGER", ["Check Tools Status", "Install Tools", "Add Custom Tool", "Tool Information"])
        tools = all_tools()
        if c == "0": return
        if c == "1":
            for t in tools: print(f"[{'✓' if command_exists(t) else '✗'}] {t['name']} ({t['source']})")
        elif c == "2":
            mode = prompt_choice("INSTALL TOOLS", ["Install All Missing Tools", "Install Missing Tools by Category", "Install a Specific Official Tool"])
            if mode == "1":
                missing = [t for t in tools if t["source"] == "official" and not command_exists(t)]
                print("Missing:", ", ".join(t["name"] for t in missing) or "none")
                if integrity_ok and missing and confirm("Install all listed official tools?"):
                    for t in missing: install_tool(t)
            elif mode == "2":
                cats = sorted({t.get("category", "Other") for t in tools})
                x = prompt_choice("Choose category", cats)
                if x != "0":
                    chosen = cats[int(x)-1]; missing = [t for t in tools if t.get("category") == chosen and t["source"] == "official" and not command_exists(t)]
                    print("Missing:", ", ".join(t["name"] for t in missing) or "none")
                    if integrity_ok and missing and confirm("Install these tools?"):
                        for t in missing: install_tool(t)
            elif mode == "3":
                x = prompt_choice("Select official tool", [t["name"] for t in tools if t["source"] == "official"])
                if x != "0":
                    official = [t for t in tools if t["source"] == "official"]; t = official[int(x)-1]
                    print(f"Category: {t.get('category','Other')}")
                    if integrity_ok: install_tool(t)
        elif c == "3": custom_tool_manager()
        elif c == "4":
            x = prompt_choice("Select tool", [t["name"] for t in tools])
            if x != "0": tool_info(tools[int(x)-1])

def add_custom_tool():
    print("\nCustom tools are local only and never enter the official catalog.")
    name = input("Tool name: ").strip(); command = input("Executable path or command: ").strip()
    if not name or not command: print("[!] Name and command are required."); return
    if not os.path.isabs(command): print("[!] Use an absolute executable path for a custom tool."); return
    if not Path(command).exists(): print("[!] Executable path does not exist."); return
    item = {"name": name, "category": input("Category: ").strip() or "Custom", "description": input("Description: ").strip(), "command": command, "launch_command": command, "check_command": command, "type": "custom", "created_at": now()}
    CUSTOM_DIR.mkdir(parents=True, exist_ok=True); write_json(CUSTOM_DIR / f"{safe_name(name)}.json", item); log_event("CUSTOM_TOOL_ADDED", name); print("[✓] Custom tool added locally.")

def custom_tool_manager():
    while True:
        c = prompt_choice("CUSTOM TOOL MANAGER", ["Add Local Tool", "Fetch from GitHub", "Fetch from Direct URL", "List My Custom Tools", "Remove Custom Tool"])
        if c == "0": return
        if c == "1": add_custom_tool()
        elif c == "2": fetch_custom_tool("github")
        elif c == "3": fetch_custom_tool("url")
        elif c == "4":
            tools = [t for t in all_tools() if t.get("source") == "custom"]
            for t in tools: print(f"- {t['name']} | {t.get('category','Custom')} | {t.get('path', t.get('command','-'))}")
        elif c == "5":
            tools = [t for t in all_tools() if t.get("source") == "custom"]
            x = prompt_choice("Select custom tool to remove", [t["name"] for t in tools])
            if x != "0":
                t = tools[int(x)-1]; p = Path(t.get("definition", ""))
                if p.exists() and confirm(f"Remove local custom tool {t['name']}?"): p.unlink(); print("[✓] Custom tool removed.")

def fetch_custom_tool(kind):
    source = input("GitHub repository URL: " if kind == "github" else "Direct file URL: ").strip()
    if not (source.startswith("https://") or source.startswith("http://")):
        print("[!] Only HTTP/HTTPS URLs are accepted."); return
    name = input("Local tool name: ").strip(); category = input("Category: ").strip() or "Custom"; description = input("Description: ").strip()
    if not name: print("[!] Tool name is required."); return
    target = CUSTOM_DIR / safe_name(name); target.mkdir(parents=True, exist_ok=True)
    archive = target / "source.zip" if kind == "github" else target / "downloaded_file"
    if kind == "github":
        parts = source.rstrip("/").split("/")
        if len(parts) < 5 or parts[2] != "github.com": print("[!] Use a GitHub repository URL such as https://github.com/OWNER/REPO"); return
        owner, repo = parts[3], parts[4].removesuffix(".git")
        try:
            request = urllib.request.Request(f"https://api.github.com/repos/{owner}/{repo}", headers={"User-Agent": "KeepTrace-Custom-Fetcher"})
            with urllib.request.urlopen(request, timeout=20) as response: metadata = json.loads(response.read().decode())
            branch = metadata.get("default_branch", "main")
        except Exception:
            branch = "main"
        download_url = f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}"
    else: download_url = source
    print("Source:", download_url); print("Destination:", target)
    if not confirm("Download this custom tool locally?"): return
    try:
        urllib.request.urlretrieve(download_url, archive)
        if kind == "github":
            safe_extract_zip(archive, target / "source")
        print("SHA-256:", sha256(archive))
    except Exception as e:
        print("[!] Download failed:", e); return
    launch = input("Executable path or command (absolute path, or relative path after download): ").strip()
    if not launch: print("[!] No launch command supplied; source was saved but not registered."); return
    if not launch.startswith("/"): launch = str(target / "source" / launch)
    item = {"name": name, "category": category, "description": description, "command": launch, "launch_command": launch, "check_command": launch, "type": "custom", "source_url": source, "path": str(target), "created_at": now()}
    executable = Path(launch)
    if executable.is_file():
        try: executable.chmod(executable.stat().st_mode | 0o111)
        except OSError: pass
    write_json(CUSTOM_DIR / f"{safe_name(name)}.json", item); log_event("CUSTOM_TOOL_FETCHED", name); print("[✓] Custom tool saved only in this user's KeepTrace.")

def case_dirs(): return sorted([p for p in CASES_DIR.iterdir() if p.is_dir()]) if CASES_DIR.exists() else []
def new_case():
    name = input("Case name (English, spaces become -): ").strip()
    if not name:
        print("[!] Case name cannot be empty."); return None
    desc = input("Description (optional): ").strip(); ident = f"KT-{datetime.now().strftime('%Y%m%d-%H%M%S')}"; folder = CASES_DIR / f"{ident}-{safe_name(name)}"
    for sub in ["evidence", "tool_output", "findings", "notes", "timeline", "reports", "hashes"]: (folder / sub).mkdir(parents=True, exist_ok=True)
    meta = {"case_id": ident, "name": name, "description": desc, "created_at": now(), "status": "Open", "evidence": [], "findings": [], "timeline": [], "analyses": []}; write_json(folder / "case.json", meta); append_activity(folder, "CASE_CREATED", ident)
    index = read_json(CASES_INDEX, []); index.append({"case_id": ident, "name": name, "created_at": meta["created_at"], "status": "Open", "case_path": folder.name}); write_json(CASES_INDEX, index)
    print(f"[✓] Case created: {ident}"); return folder

def append_activity(folder, action, detail):
    with (folder / "activity_log.jsonl").open("a") as f: f.write(json.dumps({"timestamp": now(), "action": action, "detail": detail}, ensure_ascii=False) + "\n")

def mark_analysis_complete(folder, analysis_id, return_code):
    meta = read_json(folder / "case.json", {})
    for analysis in meta.get("analyses", []):
        if analysis.get("analysis_id") == analysis_id:
            analysis["status"] = "completed" if return_code == 0 else "failed"
            analysis["ended_at"] = now()
            write_json(folder / "case.json", meta)
            append_activity(folder, "TOOL_FINISHED", f"{analysis_id} {analysis['status']}")
            return

def select_case():
    cases = case_dirs(); x = prompt_choice("Select case", [f.name for f in cases]); return None if x == "0" else cases[int(x)-1]

def change_case_status(folder, status):
    meta = read_json(folder / "case.json", {})
    if status == "Closed" and not confirm("Close this case?"): return
    meta["status"] = status; meta["closed_at"] = now() if status == "Closed" else meta.get("closed_at")
    write_json(folder / "case.json", meta)
    index = read_json(CASES_INDEX, [])
    for item in index:
        if item.get("case_path") == folder.name: item["status"] = status
    write_json(CASES_INDEX, index); append_activity(folder, "CASE_STATUS_CHANGED", status); print(f"[✓] Case status: {status}")
def add_evidence(folder):
    if read_json(folder / "case.json", {}).get("status") != "Open": print("[!] Case is not open. Reopen it first."); return
    source = Path(input("Evidence file path: ").strip()).expanduser()
    if not source.is_file(): print("[!] File not found."); return
    meta = read_json(folder / "case.json", {}); eid = f"E-{len(meta.get('evidence', []))+1:04d}"; dest = folder / "evidence" / f"{eid}_{source.name}"; shutil.copy2(source, dest); h = sha256(dest); item = {"id": eid, "name": source.name, "original_path": str(source), "stored_path": str(dest.relative_to(folder)), "sha256": h, "added_at": now()}; meta["evidence"].append(item); write_json(folder / "case.json", meta); (folder / "hashes" / "evidence_hashes.csv").write_text("evidence_id,filename,sha256,added_at\n" + "\n".join(f"{e['id']},{e['name']},{e['sha256']},{e['added_at']}" for e in meta["evidence"]) + "\n"); append_activity(folder, "EVIDENCE_ADDED", f"{eid} {source.name}"); print(f"[✓] Added {eid}; SHA-256: {h}")
def add_finding(folder):
    if read_json(folder / "case.json", {}).get("status") != "Open": print("[!] Case is not open. Reopen it first."); return
    meta = read_json(folder / "case.json", {}); evid = meta.get("evidence", []); title = input("Finding title: ").strip(); value = input("Value/details: ").strip(); desc = input("Description: ").strip(); ts = input("Event timestamp (optional): ").strip(); source = prompt_choice("Related evidence", [f"{e['id']} - {e['name']}" for e in evid]) if evid else "0"; eid = evid[int(source)-1]["id"] if source != "0" else None; fid = f"F-{len(meta.get('findings', []))+1:04d}"; item = {"id": fid, "title": title, "value": value, "description": desc, "timestamp": ts or None, "evidence_id": eid, "created_at": now()}; meta["findings"].append(item); write_json(folder / "case.json", meta); append_activity(folder, "FINDING_ADDED", fid); print(f"[✓] Finding saved: {fid}");

def show_case(folder):
    meta = read_json(folder / "case.json", {}); print(f"\nCASE: {meta.get('name')} | {meta.get('case_id')} | {meta.get('status')}\nCreated: {meta.get('created_at')}\nEvidence: {len(meta.get('evidence', []))} | Findings: {len(meta.get('findings', []))} | Analyses: {len(meta.get('analyses', []))}")
    for e in meta.get("evidence", []): print(f"  {e['id']} {e['name']} {e['sha256'][:16]}...")

def view_evidence(folder):
    evid = read_json(folder / "case.json", {}).get("evidence", [])
    x = prompt_choice("EVIDENCE", [f"{e['id']} {e['name']} | {e['sha256'][:16]}..." for e in evid])
    if x == "0": return
    e = evid[int(x)-1]; meta = read_json(folder / "case.json", {}); runs = [a for a in meta.get("analyses", []) if a.get("evidence_id") == e["id"]]
    print(f"\nEvidence: {e['id']}\nFile: {e['name']}\nStored: {e['stored_path']}\nSHA-256: {e['sha256']}\nAdded: {e['added_at']}\nRelated analyses: {len(runs)}")
    for a in runs: print(f"  {a['analysis_id']} | {a['tool']} | {a.get('status')} | {a.get('output_file','-')}")

def view_tool_runs(folder):
    meta = read_json(folder / "case.json", {}); analyses = meta.get("analyses", [])
    if not analyses:
        print("No tool analyses recorded yet."); return
    x = prompt_choice("TOOL ANALYSES", [f"{a['analysis_id']} | {a['tool']} | {a.get('status')}" for a in analyses])
    if x == "0": return
    a = analyses[int(x)-1]; output = folder / a.get("output_file", "")
    print(f"\nAnalysis: {a['analysis_id']}\nTool: {a['tool']}\nCommand: {a.get('command','-')}\nInput evidence: {a.get('evidence_id') or '-'}\nOutput: {a.get('output_file','-')}\nStatus: {a.get('status','-')}")
    action = prompt_choice("ANALYSIS ACTIONS", ["View Result", "Promote Result to Evidence", "Back"])
    if action == "1":
        if output.exists():
            print("\n--- ANALYSIS RESULT ---")
            print(output.read_text(errors="replace"))
            print("--- END RESULT ---")
        else: print("[!] Result file is not available.")
    elif action == "2": promote_analysis_result(folder, a)

def promote_analysis_result(folder, analysis):
    meta = read_json(folder / "case.json", {})
    if analysis.get("promoted_to_evidence_id"):
        print(f"[!] Already promoted as {analysis['promoted_to_evidence_id']}."); return
    source = folder / analysis.get("output_file", "")
    if not source.exists(): print("[!] Result file is not available."); return
    eid = f"E-{len(meta.get('evidence', []))+1:04d}"
    dest = folder / "evidence" / f"{eid}_{source.name}"
    shutil.copy2(source, dest); h = sha256(dest)
    item = {"id": eid, "name": dest.name, "original_path": str(source), "stored_path": str(dest.relative_to(folder)), "sha256": h, "added_at": now(), "evidence_type": "derived", "derived_from_analysis": analysis["analysis_id"], "derived_from_tool": analysis["tool"]}
    meta.setdefault("evidence", []).append(item); analysis["promoted_to_evidence_id"] = eid
    (folder / "hashes" / "evidence_hashes.csv").write_text("evidence_id,filename,sha256,added_at\n" + "\n".join(f"{e['id']},{e['name']},{e['sha256']},{e['added_at']}" for e in meta["evidence"]) + "\n")
    write_json(folder / "case.json", meta); append_activity(folder, "ANALYSIS_PROMOTED_TO_EVIDENCE", f"{analysis['analysis_id']} -> {eid}")
    print(f"[✓] Result promoted to {eid}; SHA-256: {h}")

def case_workspace():
    while True:
        c = prompt_choice("CASE WORKSPACE", ["Create New Case", "Open Existing Case", "List Cases"])
        if c == "0": return
        if c == "1": folder = new_case()
        elif c in ("2", "3"):
            if c == "3":
                for p in case_dirs(): print("-", p.name)
                continue
            folder = select_case()
            if not folder: continue
        else: continue
        while folder:
            x = prompt_choice(f"CASE: {folder.name}", ["View Case Details", "View Evidence", "Add Evidence", "Add Extracted Finding", "View Findings", "View Tool Runs", "View Activity Log", "Export Timeline CSV/JSON", "Close Case", "Reopen Case", "Archive Case"])
            if x == "0": break
            if x == "1": show_case(folder)
            elif x == "2": view_evidence(folder)
            elif x == "3": add_evidence(folder)
            elif x == "4": add_finding(folder)
            elif x == "5":
                for f in read_json(folder / "case.json", {}).get("findings", []): print(f"{f['id']} | {f['title']} | {f.get('timestamp') or 'undated'} | {f.get('evidence_id') or '-'}")
            elif x == "6": view_tool_runs(folder)
            elif x == "7":
                try: print((folder / "activity_log.jsonl").read_text())
                except FileNotFoundError: pass
            elif x == "8": export_timeline(folder)
            elif x == "9": change_case_status(folder, "Closed")
            elif x == "10": change_case_status(folder, "Open")
            elif x == "11": change_case_status(folder, "Archived")

def export_timeline(folder):
    meta = read_json(folder / "case.json", {}); rows = [f for f in meta.get("findings", []) if f.get("timestamp")]; rows.sort(key=lambda x: x["timestamp"]); out = folder / "timeline"; out.mkdir(exist_ok=True); write_json(out / "timeline.json", rows)
    with (out / "timeline.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["id", "timestamp", "title", "value", "evidence_id", "description"]); w.writeheader(); w.writerows({k: r.get(k) for k in w.fieldnames} for r in rows)
    print(f"[✓] Exported {len(rows)} dated findings to timeline/.")

def main():
    if len(sys.argv) == 5 and sys.argv[1] == "--mark-analysis":
        mark_analysis_complete(Path(sys.argv[2]), sys.argv[3], int(sys.argv[4])); return
    for p in [CUSTOM_DIR, CASES_DIR, LOG_DIR, VENV_DIR]: p.mkdir(parents=True, exist_ok=True)
    integrity_ok = verify_integrity(); print(BANNER)
    while True:
        c = prompt_choice("MAIN MENU", ["Network Forensics", "Disk & File System Forensics", "Memory Forensics", "Malware Analysis", "Windows Forensics", "Linux Forensics", "Endpoint & Incident Response", "Digital Investigation", "Tool Manager", "Case Workspace"])
        if c == "0": print("Keep learning. Keep investigating."); return
        if c == "9": tool_manager(integrity_ok)
        elif c == "10": case_workspace()
        elif c in [str(i) for i in range(1,9)]:
            cat = ["Network Forensics", "Disk & File System Forensics", "Memory Forensics", "Malware Analysis", "Windows Forensics", "Linux Forensics", "Endpoint & Incident Response", "Digital Investigation"][int(c)-1]
            ts = [t for t in all_tools() if t.get("category") == cat]
            if not ts:
                print(f"\n{cat}\nNo tools are currently registered in this category.")
                continue
            x = prompt_choice(cat, [t["name"] for t in ts])
            if x != "0" and x.isdigit() and 1 <= int(x) <= len(ts): tool_menu(ts[int(x)-1], integrity_ok)
            elif x != "0": print("[!] Invalid selection.")
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] KeepTrace closed by user.")
        sys.exit(130)
