from transformers import AutoModel
m = AutoModel.from_pretrained(p, trust_remote_code=False)
