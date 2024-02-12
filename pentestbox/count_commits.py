import requests
import argparse
import os
import re
from collections import defaultdict


def parse_repository_argument(repo_arg):
    """
    Parse the repository argument to extract the owner and repo name.
    Supports both URL and 'owner/repo' formats.
    """
    pattern = re.compile(r"(?:https?://github\.com/)?([^/]+)/([^/]+)")
    match = pattern.match(repo_arg)
    if match:
        return match.groups()
    else:
        raise ValueError("Invalid repository format. Use 'https://github.com/owner/repo' or 'owner/repo'.")


def fetch_contributions(owner, repo, contributions, authorize=False):
    """
    Fetch contributions for a single repository and update the contributions dictionary.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/contributors"
    headers = {'Accept': 'application/vnd.github.v3+json'}

    if authorize:
        token = os.getenv('GIT_PERSONAL_ACCESS_TOKEN')
        if not token:
            print("Authorization requested but GIT_PERSONAL_ACCESS_TOKEN environment variable not set.")
            return
        headers['Authorization'] = f'token {token}'

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        repo_contributors = response.json()
        for contributor in repo_contributors:
            contributions[contributor['login']] += contributor['contributions']
    else:
        print(f"Error fetching contributors for {owner}/{repo}: {response.status_code}")


def process_repositories(repositories, contributions, authorize=False):
    for repo_arg in repositories:
        try:
            owner, repo = parse_repository_argument(repo_arg)
            fetch_contributions(owner, repo, contributions, authorize)
        except ValueError as e:
            print(f"Error: {e}")


def main():
    parser = argparse.ArgumentParser(description="Sum up commits per person across multiple GitHub repositories.")
    parser.add_argument('repositories', nargs='*',
                        help="One or more GitHub repository URLs or in the format owner/repo.")
    parser.add_argument('-a', '--authorize', action='store_true',
                        help="Authorize with GitHub API using personal access token.")
    parser.add_argument('-f', '--file', type=str,
                        help="Path to a file containing one GitHub repository URL or owner/repo per line.")
    args = parser.parse_args()

    contributions = defaultdict(int)

    # Process repositories specified directly via command-line arguments
    if args.repositories:
        process_repositories(args.repositories, contributions, args.authorize)

    # Process repositories specified in a file
    if args.file:
        try:
            with open(args.file, 'r') as file:
                repo_list = [line.strip() for line in file if line.strip()]
                process_repositories(repo_list, contributions, args.authorize)
        except FileNotFoundError:
            print(f"Error: File not found: {args.file}")

    # Print aggregated contributions
    print("Aggregated Contributions:")
    for contributor, total_contributions in sorted(contributions.items(), key=lambda item: item[1], reverse=True):
        print(f"{contributor}: {total_contributions} contributions")


if __name__ == "__main__":
    main()
