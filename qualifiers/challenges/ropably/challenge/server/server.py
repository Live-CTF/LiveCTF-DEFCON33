#!/usr/bin/env python3

import base64
import os
import random
import select
import subprocess
import sys
from pathlib import Path

NUM_ROUNDS = 20
ROUND_TIMEOUT = 10.0

CHALLENGES_PATH = Path('./samples')

def do_round(challenge_path: str) -> bool:
    with open(challenge_path, "rb") as fin:
        challenge_b64 = base64.b64encode(fin.read()).decode()

    print(f"Crackme: {challenge_b64}")
    # Using input() for prompt prints to stderr for non-TTY
    print("Password: ", end="", flush=True)
    if not (stdin := select.select([sys.stdin], [], [], ROUND_TIMEOUT)[0]):
        return False

    user_password = stdin[0].readline().strip()

    try:
        p = subprocess.run(
            [challenge_path],
            input=user_password.encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        challenge_output = p.stdout
        correct_password = challenge_output.decode().strip() == "Yes"
    except:
        return False

    return correct_password

def do_game(num_rounds: int) -> bool:
    challenges = list(CHALLENGES_PATH.glob('challenge_*'))
    if len(challenges) < num_rounds:
        raise ValueError(f'Not enough challenges found: {len(challenges)} < {num_rounds}')
    challenges = random.sample(challenges, k=num_rounds)

    for round_number, challenge_path in enumerate(challenges):
        print(f"Round {round_number+1}/{len(challenges)}")
        round_result = do_round(str(challenge_path))
        if round_result:
            print("Correct!")
        else:
            print("Incorrect! Goodbye")
            return False
    return True


def main() -> int:
    try:
        flag = os.environ["FLAG"]
    except KeyError:
        print("Flag environment variable not set")
        return 1

    if do_game(NUM_ROUNDS):
        print(f"Congratulations! Here is the flag: {flag}")
    else:
        print("You failed! Please try again")

    return 0


if __name__ == "__main__":
    sys.exit(main())
