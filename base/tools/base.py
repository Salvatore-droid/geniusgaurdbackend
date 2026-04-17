# base/tools/base.py
import subprocess
import json
import re
import tempfile
import os
from typing import Dict, List, Optional
import asyncio

class BaseToolRunner:
    """Base class for all security tool integrations"""
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.config = config or {}
        self.temp_dir = tempfile.mkdtemp()
        self.results = {}
        
    async def run_command(self, cmd: List[str], timeout: int = 300) -> tuple:
        """Run shell command asynchronously"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            return stdout.decode('utf-8', errors='ignore'), stderr.decode('utf-8', errors='ignore')
        except asyncio.TimeoutError:
            process.kill()
            return "", "Timeout"
        except Exception as e:
            return "", str(e)
    
    def clean_output(self, output: str) -> str:
        """Clean tool output"""
        # Remove ANSI color codes
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', output)