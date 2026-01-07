"""
Munnawn Gill
Agentic Vulnerability Analysis Through LLM
This script performs multi-prompt analysis with Gemini on a GitLab SAST vulnerability report.
It connects to a GitLab MCP server through TCP and does the following:
1: Fetch the context of the project (README, code related to an issue)
2: Analyze the vulnerability.
3: Come up with a suggested action to take and create/assign a new task to developers.
-------
ENV VARS REQUIRED:
create a .env file with the following variables:
- GEMINI_API_KEY: Your LLM API key.
- MCP_HOST: The Hostname/IP of the Gitlab MCP Server.
- MCP_Port: The Port of the Gitlab MCP Server.
- GITLAB_PROJECT_ID: The ID number of the Gitlab Project.
-------
USAGE
You can run the script from the command line:
python llm_analysis.py

If you import this script into another Python file it can be used like this:
    import llm_analysis

    report = llm_analysis.run_analysis("path/to/sast_report.json")
    print(report)
"""

import google.generativeai as genai
import os
import json
import socket
import time
from dotenv import load_dotenv

load_dotenv(override=True)

api_key = os.getenv('GEMINI_API_KEY')
if not api_key:
    raise ValueError("GEMINI_API_KEY environment variable not set.")
genai.configure(api_key=api_key)

MCP_HOST = os.getenv('MCP_HOST', 'localhost')
MCP_PORT = int(os.getenv('MCP_PORT', 3002))
GITLAB_PROJECT_ID = os.getenv('GITLAB_PROJECT_ID', '26166')

if not GITLAB_PROJECT_ID:
    raise ValueError("GITLAB_PROJECT_ID environment variable not set.")

model = genai.GenerativeModel('gemini-2.5-pro')

fs_final_output = """
custom_impact_score: High,
justification: Critical buffer overflow allowing arbitrary code execution.,
suggestion: Replace gets() with fgets().,
vulnerability_explanation: The gets function does not check buffer length.,
impact_analysis: Potential for full system compromise via RCE.
"""

class SimpleMCPClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
        self.request_id = 1
        self.buffer = b""

    def connect(self):
        print(f"MCP: Connecting to {self.host}:{self.port}")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            self._perform_handshake()
        except Exception as e:
            print(f"Error connecting to MCP: {e}")
            self.sock = None

    def _send(self, payload):
        if not self.sock: raise ConnectionError("Not connected")
        message = json.dumps(payload) + "\n"
        self.sock.sendall(message.encode('utf-8'))

    def _receive(self):
        if not self.sock: raise ConnectionError("Not connected")
        while True:
            if b"\n" in self.buffer:
                line, self.buffer = self.buffer.split(b"\n", 1)
                if not line.strip(): continue
                return json.loads(line.decode('utf-8'))
            chunk = self.sock.recv(8192)
            if not chunk: raise ConnectionError("Socket closed")
            self.buffer += chunk

    def _perform_handshake(self):
        payload = {
            "jsonrpc": "2.0", "id": self.request_id, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "llm-agent", "version": "1.0"}}
        }
        req_id = self.request_id
        self.request_id += 1
        self._send(payload)
        
        while True:
            resp = self._receive()
            if resp.get("id") == req_id:
                if "error" in resp: raise RuntimeError(f"Handshake failed: {resp['error']}")
                break
        
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        print("MCP: Handshake successful")

    def call_tool(self, tool_name, arguments):
        if not self.sock: return "Error: Not connected"
        print(f"MCP: Calling tool '{tool_name}'")
        
        req_id = self.request_id
        payload = {
            "jsonrpc": "2.0", "id": req_id, "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments}
        }
        self.request_id += 1
        self._send(payload)
        
        while True:
            resp = self._receive()
            if "id" not in resp: continue 
            if resp["id"] == req_id:
                # DEBUG: Print Raw Response to help troubleshooting
                # print(f"DEBUG RAW RESPONSE: {str(resp)[:300]}...") 
                if "error" in resp: return f"MCP Tool Error: {resp['error']}"
                return resp.get("result", {})

    def close(self):
        if self.sock: self.sock.close()

def parse_mcp_content_string(mcp_result):
    """Helper to extract JSON data that might be wrapped in a text string."""
    if isinstance(mcp_result, dict) and 'content' in mcp_result:
        content_block = mcp_result['content']
        if isinstance(content_block, list) and len(content_block) > 0:
            text_content = content_block[0].get('text', '')
            # Try to parse if it looks like JSON, otherwise return text
            try:
                return json.loads(text_content)
            except json.JSONDecodeError:
                return text_content
    return mcp_result

def get_repo_context(client, file_path, line_number):
    """Fetches README and specific file snippet."""
    repo_desc = "Context unavailable"
    code_snip = "Context unavailable"

    # Get README
    readme_res = client.call_tool("get_file_contents", {
        "project_id": GITLAB_PROJECT_ID, "file_path": "README.md", "ref": "main"
    })
    parsed_readme = parse_mcp_content_string(readme_res)
    if isinstance(parsed_readme, dict) and 'content' in parsed_readme:
        repo_desc = parsed_readme['content']

    # Get Code
    code_res = client.call_tool("get_file_contents", {
        "project_id": GITLAB_PROJECT_ID, "file_path": file_path, "ref": "main"
    })
    parsed_code = parse_mcp_content_string(code_res)
    
    full_code = ""
    if isinstance(parsed_code, dict) and 'content' in parsed_code:
        full_code = parsed_code['content']
    
    if full_code:
        lines = full_code.splitlines()
        start = max(0, line_number - 3)
        end = min(len(lines), line_number + 2)
        formatted_lines = []
        for i, line in enumerate(lines[start:end]):
            curr = start + i + 1
            prefix = "--> " if curr == line_number else "    "
            formatted_lines.append(f"{prefix}{curr}: {line}")
        code_snip = "\n".join(formatted_lines)

    return repo_desc, code_snip

def get_project_members(client):
    """Fetches the list of developers on the project."""
    print("Fetching project members...")
    res = client.call_tool("list_project_members", {"project_id": GITLAB_PROJECT_ID})
    
    # The tool likely returns a list of member objects
    members_data = parse_mcp_content_string(res)
    
    if isinstance(members_data, list):
        # Format explicitly for the LLM
        return "\n".join([f"- ID: {m['id']}, Name: {m['name']}, Username: {m['username']}" for m in members_data])
    return "Could not fetch members list."

def create_gitlab_issue(client, issue_data):
    """Creates the issue using the decision from the LLM."""
    print(f"Creating Issue: {issue_data['title']} (Assignee: {issue_data.get('assignee_ids')})")
    
    return client.call_tool("create_issue", {
        "project_id": GITLAB_PROJECT_ID,
        "title": issue_data['title'],
        "description": issue_data['description'],
        "assignee_ids": issue_data['assignee_ids'],
        "labels": ["Security", "LLM-Triage"]
    })

def parse_sast_json(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    vuln = data['vulnerabilities'][0]
    return (
        vuln['location']['file'], 
        vuln['description'], 
        vuln['severity'], 
        "CWE-Unknown", 
        vuln['location'].get('start_line', 1)
    )

def parse_llm_json(text):
    text = text.replace('```json', '').replace('```', '').strip()
    return json.loads(text)

def run_analysis(sast_json_path):
    client = SimpleMCPClient(MCP_HOST, MCP_PORT)
    client.connect()
    if not client.sock: return "Failed to connect to MCP"

    try:
        # 1. Parse Input
        file_name, desc, severity, cwe, line_num = parse_sast_json(sast_json_path)
        print(f"--- Analyzing {file_name} (Line {line_num}) ---")

        # 2. Get Context
        repo_desc, code_snip = get_repo_context(client, file_name, line_num)
        print(f"Context Acquired")
        print(f"Project README Snippet:\n{repo_desc[:500]}\n...\n")
        print(f"Code Snippet:\n{code_snip[:500]}\n...\n")

        # 3. LLM Analysis (Prompt 1 & 2)
        prompt_analysis = f"""
        ROLE: Expert Security Analyst.
        VULNERABILITY: {desc} (Severity: {severity})
        LOCATION: {file_name}:{line_num}
        CODE: {code_snip}
        REPO CONTEXT: {repo_desc[:500]}...
        
        OUTPUT: Provide a detailed impact analysis and specific fix suggestion.
        """
        resp_analysis = model.generate_content(prompt_analysis).text

        prompt_format = f"""
        ROLE: Expert Security Analyst.

        TASK: 
        1. Review the INPUT analysis below for technical accuracy and clarity.
        2. Refine the language to be professional and actionable.
        3. Format the final result into the strict REQUIRED OUTPUT JSON schema.

        INPUT: {resp_analysis}
        FORMATTING EXAMPLES: {fs_final_output}
        REQUIRED OUTPUT JSON: {{ "custom_impact_score": "...", "justification": "...", "suggestion": "...", "vulnerability_explanation": "...", "impact_analysis": "..." }}
        """
        final_report_json = parse_llm_json(model.generate_content(prompt_format).text)
        print("\n--- Vulnerability Analyzed ---")
        print(json.dumps(final_report_json, indent=2))

        # 4. Agentic Task Assignment
        print("\n--- Initiating Task Assignment ---")
        
        # A. Get Developers
        members_list = get_project_members(client)
        print(f"Developers Found:\n{members_list}")

        # B. LLM Decision
        prompt_assign = f"""
        ROLE: Engineering Manager.
        TASK: Create a GitLab Issue based on the analysis below.
        
        ANALYSIS:
        - Vulnerability: {final_report_json['vulnerability_explanation']}
        - Suggestion: {final_report_json['suggestion']}
        
        AVAILABLE DEVELOPERS:
        {members_list}
        
        INSTRUCTIONS:
        1. Create a descriptive Title.
        2. Create a Description containing the explanation and suggestion.
        3. Assign to the most relevant developer ID from the list. If list is empty/error, return empty list [].
        
        OUTPUT JSON: {{ "title": "...", "description": "...", "assignee_ids": [123] }}
        """
        issue_decision = parse_llm_json(model.generate_content(prompt_assign).text)
        
        # C. Execute Tool
        issue_result = create_gitlab_issue(client, issue_decision)
        
        # D. Append Result
        final_report_json['gitlab_issue_created'] = issue_result
        return json.dumps(final_report_json, indent=2)

    except Exception as e:
        return f"Error during execution: {e}"
    finally:
        client.close()

if __name__ == "__main__":
    if os.path.exists("test1_input.json"):
        print(run_analysis("test1_input.json"))
    else:
        print("Please create test1_input.json")