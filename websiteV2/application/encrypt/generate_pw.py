import hashlib


PW_SALT = '7f6ZHW%@D6BrBP'
pw = 'helloworld' + PW_SALT
hashedpw = hashlib.sha256(pw.encode()).hexdigest()
print(hashedpw)
