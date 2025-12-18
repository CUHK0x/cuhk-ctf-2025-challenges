#!/usr/bin/env python3

import os
import tempfile

with tempfile.NamedTemporaryFile() as tmp:
	print('Send you script: ( + append "\\n-- EOF --\\n"):')
	s = input()
	while(s != '-- EOF --' and len(s) < 1024*1024):
		tmp.write((s+'\n').encode())
		s = input()
	tmp.flush()
	os.system('timeout 3 /home/ctf/qjs ' + tmp.name)