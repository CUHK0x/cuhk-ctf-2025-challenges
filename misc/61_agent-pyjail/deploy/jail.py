from local_python_executor import LocalPythonExecutor
import subprocess

local_python_executor = LocalPythonExecutor(additional_authorized_imports=[])
local_python_executor.send_tools({})

code = input("PySandbox for LLMagent> ")

try:
    result = local_python_executor(code).output
except Exception as e:
    result = str(e)
print("Result:", result)
