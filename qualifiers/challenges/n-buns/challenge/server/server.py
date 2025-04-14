#!/usr/bin/env python3

import base64
import os
import random
import select
import subprocess
import sys
from pathlib import Path


NUM_ROUNDS = 10
ROUND_TIMEOUT = 10.0

CHALLENGES_PATH = Path('./samples')
PASSWORDS_PATH = Path('./passwords')

# For local debugging, this is 0 on the server
if os.environ.get("LOCAL") == "1":
    NUM_ROUNDS = 1


def do_round(
    challenge_path: str,
    password_path: str,
) -> bool:

    with open(challenge_path, "rb") as fin:
        challenge_b64 = base64.b64encode(fin.read()).decode()

    with open(password_path, "r") as f:
        challenge_password = f.read().strip()

    print(f"Watchme: {challenge_b64}")
    # Using input() for prompt prints to stderr for non-TTY
    print("Password: ", end="", flush=True)


    if not (stdin := select.select([sys.stdin], [], [], ROUND_TIMEOUT)[0]):
        return False

    user_password = stdin[0].readline().strip()

    if user_password == challenge_password:
        return True
    else:
        return False


def do_game(num_rounds: int) -> bool:

    challenges = list(CHALLENGES_PATH.glob('challenge_*'))
    if len(challenges) < num_rounds:
        raise ValueError(f'Not enough challenges found: {len(challenges)} < {num_rounds}')

    challenges = random.sample(challenges, k=num_rounds)

    for round_number, challenge_path in enumerate(challenges):

        password_path = PASSWORDS_PATH.joinpath(challenge_path.name)
        if not password_path.exists():
            raise ValueError(f'{password_path=} not found for {challenge_path=}')

        print(f"Round {round_number+1}/{len(challenges)}")

        round_result = do_round(
            challenge_path.as_posix(),
            password_path.as_posix(),
        )
        if round_result:
            print("Correct!")
        else:
            print("Incorrect...")
            return False

    return True


def main() -> int:
    try:
        flag = os.environ["FLAG"]
    except KeyError:
        print("Flag environment variable not set")
        return 1
    
    print('LiveCTF 2025: n-buns - Instructions')
    print('Some functions have non-random names, use those names in call order to get the password.')
    print('')

    if do_game(NUM_ROUNDS):
        print(f"Boy howdy! Here's that flag: {flag}")
    else:
        print("Shucks pardner! Better luck next time")

    return 0


if __name__ == "__main__":
    sys.exit(main())
