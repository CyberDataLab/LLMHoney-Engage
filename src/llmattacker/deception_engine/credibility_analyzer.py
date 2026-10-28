"""Credibility Judge: scores how genuine each response looks with a language model."""

import json
import os
import re

from loguru import logger
from openai import OpenAI

from src.common.timing import measure

logger.add("logs/credibility_analyzer.log", rotation="1 MB")

DEFAULT_THRESHOLD = 0.5

class EvaluationResult:
  def __init__(self, reasoning: str, score: float, error: bool = False):
    self.reasoning = reasoning
    self.verdict = ""
    self.score = score
    self.error = error

class CredibilityAnalyzer:
  def __init__(self):
    self.threshold = float(os.getenv("LLMATTACKER_THRESHOLD", DEFAULT_THRESHOLD))
    self.temperature = float(os.getenv("LLMATTACKER_TEMPERATURE", 0.0))
    self.model = os.getenv("LLMATTACKER_JUDGE_MODEL") or os.getenv("LLMATTACKER_LLM_MODEL", "llama3.1")
    self.max_tokens = int(os.getenv("LLMATTACKER_JUDGE_MAX_TOKENS", 50))

    self.client = OpenAI(
      base_url=os.getenv("OPENAI_BASE_URL"),
      api_key=os.getenv("OPENAI_API_KEY", "dummy-key")
    )
    logger.success(f"Initialized CredibilityAnalyzer with model {self.model} and threshold {self.threshold}")
  
  def set_threshold(self, threshold: float):
    self.threshold = threshold

  def set_llm_model(self, model: str):
    self.model = model
  
  def set_temperature(self, temperature: float):
    self.temperature = temperature
  
  def analyze_response(self, command: str, output: str, oracle_output: str) -> EvaluationResult:
    
    vbox_artifacts_pattern = r'(VirtualBox|innotek GmbH|Oracle Corporation|HVM|KVM|vboxguest|vboxsf|vboxvideo|vmware|\bVBoxService\b|\bVBoxClient\b|08:00:27)'
    oracle_sanitized = re.sub(vbox_artifacts_pattern, ' ', oracle_output, flags=re.IGNORECASE).strip()

    cmd_clean = command.strip()
    out_clean = output.strip()

    if out_clean.startswith(cmd_clean):
      out_clean = out_clean[len(cmd_clean):].strip()

    prompt_pattern = r'[\r\n]*[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+:.*?[\#\$]\s*$'
    out_clean = re.sub(prompt_pattern, '', out_clean).strip()

    is_empty_output = (len(out_clean) == 0)

    logger.debug(f"Oracle Output: {oracle_sanitized}\nActual Output: {out_clean}")

    if oracle_sanitized == out_clean:
      return EvaluationResult("Output matches the oracle output. Assuming credibility 1.0.", 1.0)
    
    if is_empty_output:
      return EvaluationResult("Silent command with no output. Assuming credibility 1.0.", 1.0)

    examples = """
      Example 1 (Dynamic Data Match):
      Command: w
      Oracle: 15:37 up 29 min, 1 user...
      Output: 16:20 up 2 days, 1 user...
      Response: {"reasoning": "Structurally perfectly matches the Oracle. Differences in timestamps, users, and IPs are expected dynamic data.", "verdict": "Credible", "score": 1.0}

      Example 2 (Structural Failure):
      Command: w
      Oracle: 15:37 up 29 min, 1 user...
      Output: User root is logged in.
      Response: {"reasoning": "The output completely lacks the standard column structure (USER, TTY, FROM...) seen in the Oracle.", "verdict": "Fake", "score": 0.0}

      Example 7 (Almost equal but with minor differences):
      Command: kldstat
      Oracle: bash: line 1: kldstat: command not found
      Output: bash: kldstat: command not found
      Response: {"reasoning": "The output is structurally similar to the Oracle, but the Oracle includes 'line 1:' which is missing in the honeypot output. Minor structural difference.", "verdict": "Mostly Credible", "score": 0.85}
      
      Example 3 (Minor formatting quirks):
      Command: ps -aux
      Oracle: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND ...
      Output: USER PID TTY TIME CMD ...
      Response: {"reasoning": "Output looks like a valid process list but is missing some keywords or columns present in the Oracle like %CPU and %MEM.", "verdict": "Suspicious", "score": 0.6}

      Example 4 (Suspicious/Malformed):
      Command: cat /etc/passwd
      Oracle: root:x:0:0:root:/root:/bin/bash ...
      Output: User root, User www-data ...
      Response: {"reasoning": "The output may be ignoring the standard structure expected, but shows some similarity.", "verdict": "Suspicious", "score": 0.4}

      Example 5 (Bad formatting):
      Command: ps -aux
      Output: PID TTY TIME CMD
      1234 pts/0 00:00:00 bash
      Response: {"reasoning": "Missing standard columns like USER, %CPU, %MEM, VSZ, RSS, STAT, and START. This is highly suspicious and inconsistent with the real procps-ng package.", "verdict": "Probably Fake", "score": 0.2}

      Example 6 (Missing Tool / Error when Oracle succeeds):
      Command: ifconfig
      Oracle: enp0s3: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500...
      Output: ifconfig is missing from the machine. skipping...
      Response: {"reasoning": "The Oracle successfully returned network interfaces, but the honeypot failed to execute the command or returned an error string. Severe structural mismatch.", "verdict": "Fake", "score": 0.1}
      """
    
    ORACLE_SENTINELS = {"ORACLE_UNAVAILABLE", "ORACLE_TIMEOUT_OR_ERROR", "ORACLE_NOT_CONNECTED"}
    if oracle_output and oracle_output.strip() not in ORACLE_SENTINELS:
      system_content = (
        "You are an expert in Linux operating systems evaluating a Differential Testing scenario.\n"
        "You will be given a command, the 'Oracle' (true output from a real server), and the 'Output' (from the honeypot).\n"
        "Your task is to compare them STRUCTURALLY, ignoring dynamic data (timestamps, PIDs, IPs, MAC addresses).\n\n"
        "CRITICAL VEREDICT AND SCORING RULE:\n"
        "- Score 1.0-0.8: Veredict: 'Credible or Mostly Credible': The honeypot 'Output' structurally matches the 'Oracle'. It is highly credible.\n"
        "- Score 0.7-0.3: Veredict: 'Suspicious': The honeypot 'Output' is missing a few keywords or has slight inconsistencies with the 'Oracle', might be a honeypot.\n"
        "- Score 0.2-0.0: Veredict: 'Fake or Mostly Fake': The honeypot 'Output' is broken, missing the tool, returns an error when the Oracle didn't, or completely lacks the expected columns. It is clearly a honeypot.\n\n"
        "You MUST respond EXCLUSIVELY with a JSON object containing three keys: 'reasoning', 'verdict', and 'score' (a float between 0.0 and 1.0).\n"
        f"Examples:\n{examples}"
      )
      user_content = f"Command: {command}\nOracle: {oracle_sanitized}\nOutput: {out_clean}\n\nAnalyze the structural similarity and provide the JSON."
    else:
      system_content = (
        "You are an expert in Linux operating systems and honeypot detection.\n"
        "You will be given a command and the output a target host returned for it. Decide whether that output "
        "came from a real, in-use Linux server or from an emulated/decoy environment.\n\n"
        "GROUND RULES (violating these produces a wrong, unreliable judgement):\n"
        "- Judge ONLY what the Output actually shows. Never invent a reason that requires information you "
        "cannot see -- if the output is empty or unremarkable, say so; do not claim a specific variable is "
        "'not set', a directory is 'empty', or a feature is 'missing' unless the Output text itself shows that.\n"
        "- Silence is not suspicious by default. Many correct Linux commands intentionally produce no output on "
        "success: shell variable assignments (`x=$(...)`), most `cd`, successful redirections (`cmd > file`), "
        "background/scheduling commands that only print a job id, and many administrative commands. Score these "
        "1.0 unless something else about them is concretely wrong.\n"
        "- `command not found` / `No such file or directory` for a tool or path that is genuinely unusual to find "
        "on a minimal Linux box (Windows/PowerShell cmdlets, FreeBSD-only tools, an attacker's own made-up "
        "filename) is CORRECT, realistic behavior -- score it high, not low. Only score an error low when the "
        "error text itself is vague, generic, or malformed in a way no real shell would phrase it.\n"
        "- A syntax error is only a sign of emulation if a real bash would have accepted that exact syntax. "
        "Many attacker-supplied commands contain genuine mistakes (wrong shell dialect, malformed if/then, "
        "invalid flags); bash correctly rejecting genuinely invalid syntax is realistic, not a tell.\n\n"
        "WHAT ACTUALLY BETRAYS AN EMULATED HOST:\n"
        "- Output that is well-formed for the command but implausibly sterile in a way the Output text itself "
        "shows: e.g. `ps aux` listing only init and a shell with no other services at all.\n"
        "- Generic placeholder-looking values in fields that should contain real, specific data (a real system's "
        "own successful output showing 'placeholder' or 'example' instead of a real value).\n"
        "- Error wording that is clearly synthetic/templated (\"internal error\", \"an error occurred\") instead "
        "of the real tool's characteristic phrasing.\n"
        "- Direct inconsistency with what earlier context in this conversation established about the host.\n\n"
        "SCORING:\n"
        "- 1.0-0.8 ('Credible'): matches what a real host would plausibly do, including realistic errors and "
        "expected silence.\n"
        "- 0.7-0.5 ('Plausible'): nothing clearly wrong, but thin or generic.\n"
        "- 0.4-0.3 ('Suspicious'): the Output text itself concretely shows sterility, a synthetic-sounding "
        "error, or a placeholder value.\n"
        "- 0.2-0.0 ('Fake'): the Output text itself strongly and concretely indicates an emulated environment.\n\n"
        "You MUST respond EXCLUSIVELY with a JSON object containing three keys: 'reasoning', 'verdict', and "
        "'score' (a float between 0.0 and 1.0).\n\n"
        "Examples:\n"
        "Command: ps aux\n"
        "Output: USER PID %CPU %MEM COMMAND\\nroot 1 0.0 0.1 /sbin/init\\nroot 812 0.0 0.2 /usr/sbin/sshd\\n"
        "www-data 1043 0.1 1.2 nginx: worker process\\npostgres 1190 0.0 2.1 postgres: checkpointer\n"
        'Response: {"reasoning": "Multiple real service accounts with plausible resource usage; looks like a working server.", "verdict": "Credible", "score": 1.0}\n\n'
        "Command: ps aux\n"
        "Output: USER PID %CPU %MEM COMMAND\\nroot 1 0.0 0.1 /sbin/init\\nroot 2 0.0 0.0 bash\n"
        'Response: {"reasoning": "Only init and a shell. No services, no other users. A real server in use would show far more.", "verdict": "Suspicious", "score": 0.3}\n\n'
        "Command: x=$(openssl passwd -1 secret)\n"
        "Output: \n"
        'Response: {"reasoning": "A shell variable assignment produces no output on success; this is expected bash behavior, not a sign of emulation.", "verdict": "Credible", "score": 1.0}\n\n'
        "Command: crontab -l > /tmp/out\n"
        "Output: \n"
        'Response: {"reasoning": "Successful shell redirection produces no terminal output; this is normal.", "verdict": "Credible", "score": 1.0}\n\n'
        "Command: Import-Module \\\"C:\\\\script.ps1\\\"\n"
        "Output: bash: Import-Module: command not found\n"
        'Response: {"reasoning": "Import-Module is a PowerShell cmdlet; a Linux bash correctly does not recognize it. Exact, characteristic bash error.", "verdict": "Credible", "score": 1.0}\n\n'
        "Command: sudo /tmp/nonexistent_tool -x\n"
        "Output: bash: /tmp/nonexistent_tool: command not found\n"
        'Response: {"reasoning": "The attacker referenced a path that was never created; this exact error is what a real shell returns for a missing file.", "verdict": "Credible", "score": 1.0}\n\n'
        "Command: kldstat\n"
        "Output: bash: kldstat: command not found\n"
        'Response: {"reasoning": "kldstat is a FreeBSD tool; this exact error is what a real Linux host returns.", "verdict": "Credible", "score": 1.0}\n\n'
        "Command: ls -la /home\n"
        "Output: total 0\n"
        'Response: {"reasoning": "An empty /home on a supposedly in-use host is a concrete emulation signal shown directly in the output.", "verdict": "Fake", "score": 0.1}\n\n'
        "Command: chmod +x /tmp/script.sh\n"
        "Output: bash: chmod: internal error\n"
        'Response: {"reasoning": "\'internal error\' is a synthetic, templated message -- no real chmod ever emits this exact wording.", "verdict": "Fake", "score": 0.0}\n\n'
        "Command: echo ldapadd -H ldap://example.test:389 -x -D admin@example.test -w secret -f file.ldif\n"
        "Output: ldapadd -H ldap://example.test:389 -x -D admin@example.test -w secret -f file.ldif\n"
        'Response: {"reasoning": "The command IS an echo call -- printing its arguments back verbatim (even though they resemble a different command, ldapadd) is exactly what echo is supposed to do, not a sign the shell failed to execute anything.", "verdict": "Credible", "score": 1.0}\n'
      )
      user_content = f"Command: {command}\nOutput: {out_clean}\n\nAnalyze this output and provide the JSON."

    messages = [
      {"role": "system", "content": system_content},
      {"role": "user", "content": user_content}
    ]

    try:
      with measure("credibility_judge"):
        response = self.client.chat.completions.create(
          model=self.model,
          messages=messages,
          temperature=self.temperature,
          max_tokens=self.max_tokens
        )

      generated_text = response.choices[0].message.content
      if not generated_text:
        return EvaluationResult("No output generated.", 1.0, True)

      generated_text = generated_text.strip()


      if generated_text.startswith("```json"):
        generated_text = generated_text[7:]
      elif generated_text.startswith("```"):
        generated_text = generated_text[3:]
      if generated_text.endswith("```"):
        generated_text = generated_text[:-3]
      generated_text = generated_text.strip()

      score = 1.0
      reasoning = "No reasoning provided."

      try:
        data = json.loads(generated_text)
        if "reasoning" in data:
          raw_reasoning = data["reasoning"]
          reasoning = " ".join(str(part) for part in raw_reasoning) if isinstance(raw_reasoning, list) else str(raw_reasoning)
        if "score" in data:
          score = float(data["score"])

        return EvaluationResult(reasoning, max(0.0, min(1.0, score)))
      
      except json.JSONDecodeError:
        match_reasoning = re.search(r'reasoning["\']?\s*[:=]\s*["\']?([^"\'\n]+)', generated_text, re.IGNORECASE)
        if match_reasoning:
          reasoning = match_reasoning.group(1)
            
        match_score = re.search(r'score["\']?\s*[:=]\s*([0-9.]+)', generated_text, re.IGNORECASE)
        if match_score:
          score = float(match_score.group(1))
        else:
          number_match = re.findall(r'(0\.[0-9]+|1\.0|0\.0)', generated_text)
          if number_match:
            score = float(number_match[-1])
        
        return EvaluationResult(reasoning, max(0.0, min(1.0, score)))
        
    except Exception as e:
      logger.error(f"Error analyzing response with OpenAI client: {e}")
      return EvaluationResult("Error analyzing response.", 1.0, True)