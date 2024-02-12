import traceback

try:
    value = 1 / 0

except BaseException as e:
    print(f"Eror is {e}")
    traceback.print_exc()

