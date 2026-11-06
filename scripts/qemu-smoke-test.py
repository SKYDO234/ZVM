#!/usr/bin/env python3
"""Real diskless TCG probe only. Does not pretend to boot a cloud OS or create a VPS."""
import shutil
import subprocess
import sys

binary = shutil.which('qemu-system-x86_64')
if not binary:
    sys.exit('UNAVAILABLE: qemu-system-x86_64 not installed. No compatibility success claimed.')
process = subprocess.Popen([binary, '-machine', 'pc,accel=tcg', '-cpu', 'max', '-m', '64', '-nodefaults',
                            '-display', 'none', '-monitor', 'none', '-serial', 'none', '-S'],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
try:
    _, stderr = process.communicate(timeout=2)
    sys.exit('FAILED: QEMU exited: ' + stderr.decode(errors='replace'))
except subprocess.TimeoutExpired:
    print('PASS: a real paused diskless machine ran with accel=tcg for 2 seconds. This does NOT test an OS boot, cloud-init, SSH, or KVM.')
finally:
    if process.poll() is None:
        process.terminate()
        try:
            process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
