from make_smartOTP import *



def generate_X() -> str:
    # Generate a random number 
    #(note that as we will multiply each digit of X with the corresponding digit of the delta,
    # we should avoid 0)
    X = ""
    for i in range(4):
        X += str(random.randint(1, 9))
    return X

def verify_OTP(OTP: str, X: str, time_limit: int = 20) -> bool:
    #Get hash of X, convert to decimal and get the first 8 digits
    hash_X = sha256(X.encode()).hexdigest()
    hash_X = int(hash_X, 16)
    hash_X = int(str(hash_X)[:8])

    #Subtract hash of X
    OTP = modulo(int(OTP) - hash_X, 100000000)
    OTP = str(OTP).zfill(8)

    OTP = OTP[::-1] #Reverse the OTP
    #Retrive the value of seconds since last even hour
    #As we expect the OTP to be generated and verified within the same hour, this approach is valid
    otp_generation_time = ""
    for i in range(4):
        part = OTP[2*i : 2*i+2]
        otp_generation_time += str(int(part) // int(X[i]))
    otp_generation_time = int(otp_generation_time)
    seconds = seconds_since_last_even_hour()
    
    #If the current time minus seconds since last even hour and seconds of the OTP generation time since its last even hour
    #within time limit (by default 20 seconds), the OTP is valid
    if abs(seconds - otp_generation_time) < time_limit:
        return True
    else:
        return False


