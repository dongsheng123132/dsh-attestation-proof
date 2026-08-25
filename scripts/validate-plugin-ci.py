import json
from pathlib import Path
p = Path('.codex-plugin/plugin.json')
data = json.loads(p.read_text(encoding='utf-8'))
assert data['name'] == 'dsh-attestation-proof'
assert data['version'] == '0.1.0'
assert data['mcpServers'] == './.mcp.json'
assert Path('.mcp.json').is_file()
print(json.dumps({'ok': True, 'validator': 'portable-ci'}))
