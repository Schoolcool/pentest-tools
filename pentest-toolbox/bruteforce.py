import hashlib
import itertools

# The secret password and its MD5 hash
password = "abaa"
secret_hash = hashlib.md5(password.encode()).hexdigest()

# Function to compare the hash of a given password with the secret hash
def hack(test_password):
    test_hash = hashlib.md5(test_password.encode()).hexdigest()
    if secret_hash == test_hash:
        print(f"Match found: {test_password}")
        return True
    return False

# Brute force approach
chars = ['a', 'b']
for combo in itertools.product(chars, repeat=len(password)):
    test_pass = ''.join(combo)
    if hack(test_pass):
        break
