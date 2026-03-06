import json
import sys

log = json.load(open('E:/sentinel/Sentinel/sentinel_code/backend/logs/95cd46b1-edcc-493d-8a38-759b704a4a8a.json'))
for e in log['events']:
    if 'verification_reasoning' in e.get('details', {}) and e['details']['verification_reasoning']:
        with open('E:/sentinel/Sentinel/sentinel_code/backend/sqli_failure.txt', 'w') as f:
            f.write(e['details']['verification_reasoning'] + "\n\n" + e['details']['patch_diff'])
        break
