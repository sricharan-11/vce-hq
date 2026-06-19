import asyncio
from vce_hq.execution.validator import validate_command, CommandDomain

async def test():
    # Example command the agent might use to get Cloud Monitoring API request_count
    cmd = '''python -c "
import urllib.request
req = urllib.request.Request('https://monitoring.googleapis.com/v3/projects/my-project/timeSeries?filter=metric.type%3D%22serviceruntime.googleapis.com%2Fapi%2Frequest_count%22')
with urllib.request.urlopen(req) as response:
    print(response.read())
"'''
    print("Testing command...")
    result = await validate_command(cmd, CommandDomain.CLOUD)
    print("Result:", result)

asyncio.run(test())
