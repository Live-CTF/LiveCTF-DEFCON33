#!/usr/bin/env python3

import argparse
import hmac
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import BinaryIO

import checker
import obfuscator


def generate_challenge(seed: bytes, outfile: BinaryIO) -> str:
    with tempfile.TemporaryDirectory("ropably") as tmpdir:
        main_o_path = tmpdir / Path("main.o")
        checker_c_path = tmpdir / Path("checker.c")
        checker_s_path = tmpdir / Path("checker.S")
        checker_o_path = tmpdir / Path("checker.o")
        checker_obf_s_path = tmpdir / Path("checker-obf.S")
        challenge_tmp_path = tmpdir / Path("challenge")

        subprocess.check_call(
            ["gcc", "-c", "-Wall", "-Wpedantic", "-o", main_o_path, "main.c"]
        )

        with open(checker_c_path, "w") as checker_c:
            password = checker.generate_checker(seed, checker_c)

        subprocess.check_call(
            [
                "gcc",
                "-ffunction-sections",
                "-fno-asynchronous-unwind-tables",
                "-ffixed-rbx",
                "-S",
                "-Wall",
                "-Wpedantic",
                "-o",
                checker_s_path,
                checker_c_path,
            ]
        )

        with open(checker_s_path, "r") as checker_s:
            with open(checker_obf_s_path, "w") as checker_s_obf:
                obfuscator.obfuscate(seed, checker_s, checker_s_obf)

        subprocess.check_call(["as", "-o", checker_o_path, checker_obf_s_path])
        subprocess.check_call(
            ["gcc", "-s", "-o", challenge_tmp_path, main_o_path, checker_o_path]
        )

        subprocess.run([challenge_tmp_path], input=password.encode(), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        with open(challenge_tmp_path, "rb") as fin:
            shutil.copyfileobj(fin, outfile)

        return password


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed-hex", required=True)
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--num-challenges", type=int, required=True)
    args = parser.parse_args()
    seed = bytes.fromhex(args.seed_hex)
    for challenge_idx in range(args.num_challenges):
        challenge_seed = hmac.digest(seed, f"{challenge_idx}".encode(), 'sha256')
        challenge_path = Path(args.output_directory) / f"challenge_{challenge_idx}"
        with open(
            challenge_path, "wb"
        ) as fout:
            challenge_password = generate_challenge(challenge_seed, fout)
        
        print(f'Generated challenge "{challenge_path}" with password "{challenge_password}"')

    return 0


if __name__ == "__main__":
    sys.exit(main())
