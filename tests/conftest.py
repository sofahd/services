import os
import sys

HERE = os.path.dirname(__file__)
# Repo root holds the `services` package (services/services/); put it on the path.
sys.path.insert(0, os.path.join(HERE, ".."))
# In the multi-repo dev checkout sofahutils is a sibling repo; in CI it is pip-installed.
_sibling_sofahutils = os.path.join(HERE, "..", "..", "sofahutils")
if os.path.isdir(_sibling_sofahutils):
    sys.path.insert(0, _sibling_sofahutils)
