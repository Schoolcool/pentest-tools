import argparse
import requests

class CatFact:
    def __init__(self, fact, length):
        self.fact = fact
        self.length = length

    def __str__(self):
        return f"Cat Fact: {self.fact} (Length: {self.length})"

def get_cat_fact():
    response = requests.get("https://catfact.ninja/fact")
    data = response.json()
    return CatFact(data['fact'], data['length'])

def main():
    parser = argparse.ArgumentParser(description="Fetch cat facts from the Cat Facts API.")
    parser.add_argument('-n', '--number', type=int, default=1, help='Number of cat facts to fetch')
    args = parser.parse_args()

    for _ in range(args.number):
        print(get_cat_fact())

if __name__ == "__main__":
    main()
