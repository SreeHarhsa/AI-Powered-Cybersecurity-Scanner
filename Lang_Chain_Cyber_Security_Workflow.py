import subprocess
import socket
import json
import logging
import time
import pytest
from typing import Dict, Any, List
import streamlit as st
from langgraph.graph import StateGraph
from dataclasses import dataclass

# Logging setup
logging.basicConfig(filename="scan.log", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Scope Enforcement
ALLOWED_DOMAINS = {"example.com", "scanme.nmap.org"}  # Define authorized domains/IPs

@dataclass
class CyberSecurityState:
    target_ip: str
    results: Dict[str, Any]
    tasks: List[str]  # Stores dynamic task list

    def dict(self) -> Dict:
        return {"target_ip": self.target_ip, "results": self.results, "tasks": self.tasks}

# Security Functions
def resolve_domain(domain: str) -> str:
    """Resolve a domain to its IP address with scope validation."""
    if domain not in ALLOWED_DOMAINS:
        logging.warning(f"Unauthorized scan attempt: {domain}")
        return None
    try:
        ip = socket.gethostbyname(domain)
        logging.info(f"Resolved {domain} to {ip}")
        return ip
    except socket.gaierror:
        logging.error(f"Failed to resolve domain: {domain}")
        return None

def run_command(command: str, retries: int = 2) -> str:
    """Run a shell command with retries."""
    for attempt in range(retries):
        try:
            result = subprocess.run(command, shell=True, text=True, capture_output=True, timeout=240)
            if result.stdout:
                logging.info(f"Executed command: {command}")
                return result.stdout.strip()
            else:
                logging.warning(f"No output for: {command}")
        except subprocess.TimeoutExpired:
            logging.warning(f"Command timed out: {command}")
        except Exception as e:
            logging.error(f"Error running command {command}: {str(e)}")
    return "❌ Command failed after retries."

# Security Tools
def nmap_scan(ip: str) -> str:
    return run_command(f"nmap -sV -sC -A -T4 {ip}")

def full_port_scan(ip: str) -> str:
    return run_command(f"nmap -p- --max-retries 2 --min-rate 5000 {ip}")

def gobuster_dir(target_url: str) -> str:
    return run_command(f"gobuster dir -u {target_url} -w /home/harsha/wordlists/common_fixed.txt")

def ffuf_scan(target_url: str) -> str:
    return run_command(f"ffuf -u {target_url}/FUZZ -w /home/harsha/wordlists/common_fixed.txt -mc 200")

# Dynamic Task Execution
def execute_task(state: CyberSecurityState, task_name: str, function) -> CyberSecurityState:
    result = function(state.target_ip)
    state.results[task_name] = result
    return CyberSecurityState(state.target_ip, state.results, state.tasks)

# Define LangGraph Workflow
workflow = StateGraph(CyberSecurityState)
workflow.add_node("Nmap Basic Scan", lambda s: execute_task(s, "Nmap Basic Scan", nmap_scan))
workflow.add_node("Full Port Scan", lambda s: execute_task(s, "Full Port Scan", full_port_scan))
workflow.add_node("Gobuster Directory Scan", lambda s: execute_task(s, "Gobuster Directory Scan", gobuster_dir))
workflow.add_node("FFUF Scan", lambda s: execute_task(s, "FFUF Scan", ffuf_scan))
workflow.add_node("Final State", lambda s: s)

# Define Workflow Sequence with Conditional Execution
workflow.set_entry_point("Nmap Basic Scan")
workflow.add_edge("Nmap Basic Scan", "Full Port Scan")
workflow.add_edge("Full Port Scan", "Gobuster Directory Scan")
workflow.add_edge("Gobuster Directory Scan", "FFUF Scan")
workflow.add_edge("FFUF Scan", "Final State")
workflow = workflow.compile()

# Unit Tests
def test_resolve_domain():
    assert resolve_domain("example.com") is not None
    assert resolve_domain("unauthorized.com") is None

def test_task_execution():
    initial_state = CyberSecurityState(target_ip="192.168.1.1", results={}, tasks=[])
    updated_state = execute_task(initial_state, "Nmap Basic Scan", lambda x: "Scan Successful")
    assert "Nmap Basic Scan" in updated_state.results
    assert updated_state.results["Nmap Basic Scan"] == "Scan Successful"

def test_run_command():
    output = run_command("echo test", retries=1)
    assert output == "test"

def test_scope_enforcement():
    assert resolve_domain("scanme.nmap.org") is not None
    assert resolve_domain("forbidden-site.com") is None

# Streamlit UI with Real-Time Updates
def main():
    st.title("🛡️ AI-Powered Cybersecurity Scanner")
    domain = st.text_input("Enter the domain to assess (Allowed: example.com, scanme.nmap.org):").strip()
    if st.button("Start Scan"):
        if domain:
            ip = resolve_domain(domain)
            if not ip:
                st.error("❌ Unauthorized domain or failed resolution.")
                return

            st.write(f"🔍 **Assessing Target:** `{domain}` (Resolved IP: `{ip}`)")
            initial_state = CyberSecurityState(target_ip=ip, results={}, tasks=[])
            final_state = workflow.invoke(initial_state)

            # Display results dynamically
            for task, output in final_state["results"].items():
                st.subheader(f"🔹 {task}")
                st.code(output, language="bash")
                time.sleep(1)  # Simulate real-time progress

            # Save report
            report = {"target": domain, "ip": ip, "results": final_state["results"]}
            with open("scan_report.json", "w") as f:
                json.dump(report, f, indent=4)
            st.success("✅ Scan completed. Report saved.")

            # Download Link
            st.download_button(
                label="📥 Download Scan Report",
                data=json.dumps(report, indent=4),
                file_name="scan_report.json",
                mime="application/json"
            )

if __name__ == "__main__":
    main()

