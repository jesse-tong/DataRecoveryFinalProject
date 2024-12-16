import random
import time
from hashlib import sha256

def modulo(a: int, b: int) -> int:
    res = a % b
    if res < 0:
        res += b
    return res

def get_last_even_hour_epoch() -> int:
    # Get the current time in seconds since the epoch
    current_time = int(time.time())
    # Get the number of seconds since the last even hour
    seconds_since_last_even_hour = current_time % 7200
    # Subtract the number of seconds since the last even hour from the current time to get the epoch time of the last even hour
    last_even_hour_epoch = current_time - seconds_since_last_even_hour
    return last_even_hour_epoch

def seconds_since_last_even_hour():
    # Get the current time in seconds since the last even hour time (0 minute and 0 second, for example 2024-10-16 10:00:00)
    return int(time.time() % 7200)

def make_smartOTP(X: str) -> str:
    delta = seconds_since_last_even_hour()
    delta = str(delta).zfill(4)
    #Smart OTP will be each digit of the delta multiplied by the corresponding digit of X concatentated
    value = ""
    for i in range(4):
        value += str(int(delta[i]) * int(X[i])).zfill(2)
    OTP = str(value).zfill(8)
    #Reverse the OTP to make it harder to guess that the OTP is based on the current time
    OTP = OTP[::-1]

    #Add hash of X, convert to decimal and get the first 8 digits
    hash_X = sha256(X.encode()).hexdigest()
    hash_X = int(hash_X, 16)
    hash_X = int(str(hash_X)[:8])

    OTP = modulo(int(OTP) + hash_X, 100000000)
    return str(OTP).zfill(8)

if __name__ == '__main__':
    input_X = input("Enter X from the program: ")
    generated_OTP = make_smartOTP(input_X)
    print(f"Generated OTP: {generated_OTP}")