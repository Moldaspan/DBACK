import uuid

def generate_verification_token():
    return str(uuid.uuid4())