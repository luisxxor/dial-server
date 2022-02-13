import sys
from string import ascii_letters, digits, punctuation
from random import choice

def generate_secret(length: int = 32) -> str:
  character_set = ascii_letters + digits + punctuation
  return ''.join([choice(character_set) for _ in range(0,length)])
