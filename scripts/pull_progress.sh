#!/bin/bash
# Show vLLM image pull progress (layers + GB) from logs/vllm_pull.log
cd "$(dirname "$0")/.."
date +%T
python3 - <<'PY'
import json,re,subprocess
out=subprocess.run(["docker","manifest","inspect","-v","nvcr.io/nvidia/vllm@sha256:9204569b17ee4c0eff75194b8e6e458479c8aee18953b5ab9cf359fcdac659e2"],capture_output=True,text=True).stdout
m=json.loads(out)
if isinstance(m,list): m=[x for x in m if x['Descriptor']['platform']['architecture']=='arm64'][0]
layers={l['digest'][7:19]:l['size'] for l in m.get('OCIManifest',m.get('SchemaV2Manifest'))['layers']}
log=open('logs/vllm_pull.log').read()
done=set(re.findall(r'^([0-9a-f]{12}): (?:Download|Pull) complete',log,re.M))
tot=sum(layers.values()); d=sum(s for k,s in layers.items() if k in done)
print(f"layers {len(done & layers.keys())}/{len(layers)} | {d/1e9:.2f}/{tot/1e9:.2f} GB | remaining {(tot-d)/1e9:.2f} GB")
for k,s in sorted(layers.items(),key=lambda x:-x[1])[:3]: print(f"  {k} {s/1e9:.2f}GB {'done' if k in done else 'pending'}")
print("EXIT line:", re.findall(r'^EXIT.*',log,re.M))
PY
r(){ awk '$1~"wlP9s9|enP7s7"{s+=$2} END{print s}' /proc/net/dev; }; a=$(r); sleep 5; b=$(r); echo "net $(( (b-a)/5/1024 )) KB/s"
