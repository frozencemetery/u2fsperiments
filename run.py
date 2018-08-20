#!/usr/bin/python3

import os
import subprocess

subprocess.check_call("make")

pipe0 = os.pipe()
pipe1 = os.pipe()

server = subprocess.Popen(["./server", "r"],
                          stdin=pipe1[0], stdout=pipe0[1])
client = subprocess.Popen(["./client", "r"],
                          stdin=pipe0[0], stdout=pipe1[1])

server.wait()
print("server done")
client.wait()
print("client done")

