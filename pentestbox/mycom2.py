import argparse
import sys


def main():
    parser = argparse.ArgumentParser(description='com2 command functionality')
    parser.add_argument('param', nargs='?', type=str, help='Primary parameter for com2')
    args = parser.parse_args()

    # Check if input is from a pipe
    if not sys.stdin.isatty():
        input_data = sys.stdin.read().strip()
        process(input_data)
    else:
        process(args.param)


def process(param):
    if param is None:
        print("No input provided for com2.")
    else:
        print(f"Processing in com1 with parameter: {param}")


if __name__ == "__main__":
    main()
