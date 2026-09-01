# Probe: can bashlex parse each line of the shared corpus?
import sys
import bashlex

for line in open(sys.argv[1]).read().strip().split("\n"):
    name, cmd = line.split("\t")
    try:
        bashlex.parse(cmd)
        print(f"OK    {name}")
    except Exception as e:
        print(f"FAIL  {name:<24} {type(e).__name__}: {str(e).splitlines()[0]}")
