import datetime
import random
import time 
from cryptography.hazmat.primitives.asymmetric import dh
from math import gcd
import time
import functools


def get_prime_and_generator():
    parameters = dh.generate_parameters(generator=2, key_size=512)
    p = parameters.parameter_numbers().p  
    g = find_generator(p)
    return p, g

def find_generator(p):
    for g in range(2, p - 1):
        if pow(g, (p - 1) // 2, p) != 1:  # Basic check for primitive root
            return g
    return 2  # Fallback

def mod_inverse(k, p_minus_1):
    return pow(k, p_minus_1 - 2, p_minus_1)  # Only works if p-1 is prime

def find_coprime(n):
    while True:
        k = random.randint(2, n-1)
        if gcd(k, n) == 1:
            return k
        
def get_timestamp():
    return datetime.datetime.now().strftime("%H:%M:%S")


def measure_time(func=None, *, label=None):
    if func is None:
        return lambda f: measure_time(f, label=label)
    
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        
        operation_name = label or func.__name__
        print(f"[TIMER] {operation_name} took {end_time - start_time:.6f} seconds")
        
        return result
    
    return wrapper


class Timer:
    def __init__(self, label="Operation"):
        self.label = label
        
    def __enter__(self):
        self.start_time = time.time()
        return self
        
    def __exit__(self, *args):
        self.end_time = time.time()
        self.execution_time = self.end_time - self.start_time
        print(f"[TIMER] {self.label} took {self.execution_time:.6f} seconds")
