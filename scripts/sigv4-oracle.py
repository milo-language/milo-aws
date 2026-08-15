import hashlib, hmac
# AWS's documented worked example (get-vanilla): the values are stable and
# published, but the point here is that Python computes the chain independently.
secret="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
date="20150830"; region="us-east-1"; service="service"
amzdate="20150830T123600Z"
canonical="\n".join(["GET","/","","host:example.amazonaws.com","x-amz-date:"+amzdate,"","host;x-amz-date",hashlib.sha256(b"").hexdigest()])
scope=f"{date}/{region}/{service}/aws4_request"
sts="\n".join(["AWS4-HMAC-SHA256",amzdate,scope,hashlib.sha256(canonical.encode()).hexdigest()])
def h(k,m): return hmac.new(k,m.encode(),hashlib.sha256).digest()
k=h(("AWS4"+secret).encode(),date); k=h(k,region); k=h(k,service); k=h(k,"aws4_request")
sig=hmac.new(k,sts.encode(),hashlib.sha256).hexdigest()
print("canonical_sha:", hashlib.sha256(canonical.encode()).hexdigest())
print("signature:    ", sig)
