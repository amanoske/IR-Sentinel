# Safe examples

`sample.txt` is a harmless static-file input. Run `python3 example/generate.py`
from the repository root to create `traversal.pcap` and `benign.pcap` here.
Supply these directly in Codex, then ask Sentinel to investigate and compare them.

The captures are generated locally with reserved documentation addresses and
`demo.invalid`. They contain a short synthetic HTTP session. The suspicious
request uses traversal-like syntax and receives a 403 response. No real traffic,
credentials, exploits or malware are included. Generated PCAPs are ignored by Git.
