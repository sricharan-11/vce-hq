import os
import re

agents_dir = r"c:\Users\spentapati\Saved Games\HC\VCE-HQ-Bv1.2\src\vce_hq\agents"

# We want to replace ("system", with ("human", ONLY outside of the `if not cache_name:` block,
# or more precisely, we only keep ("system", if it contains _SYSTEM_PROMPT or env_profile or env_context.
# Actually, looking at the code, there are things like:
# messages.append(("system", f"IMPORTANT: You are currently operating in {settings.execution_mode}."))
# messages.append(("system", f"Previous conversation context:\n{conversation}"))
#
# A safer regex:
# match lines with `("system", ` that do NOT contain `_PROMPT` and do NOT contain `env_` and do NOT contain `system_instructions`.

files_to_check = [
    "intent_analyzer.py",
    "router.py",
    "os_engineer.py",
    "cloud_engineer.py",
    "finops_agent.py",
    "security_review.py"
]

for filename in files_to_check:
    filepath = os.path.join(agents_dir, filename)
    if not os.path.exists(filepath):
        continue
    
    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()
        
    new_lines = []
    changed = False
    for line in lines:
        if '("system",' in line:
            # Check if this is the base prompt or env context
            if "_PROMPT" in line or "env_" in line or "system_instructions" in line:
                new_lines.append(line)
            else:
                new_lines.append(line.replace('("system",', '("human",'))
                changed = True
        else:
            new_lines.append(line)
            
    if changed:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
        print(f"Fixed {filename}")
    else:
        print(f"No changes for {filename}")

