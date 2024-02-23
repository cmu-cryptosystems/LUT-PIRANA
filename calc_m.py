import sys
import itertools

range = int(sys.argv[1])

for m in itertools.count():
    if m * (m-1) >= range*2:
        print(m)
        exit(0)