#!/usr/bin/env python3

import argparse
import hmac
import os
import random
import subprocess
import string
import sys
import time
from pathlib import Path
from typing import List, Dict, Tuple, Optional

import networkx as nx


USAGE = f"{sys.argv[0]} [FLAG_VALUE]"

ROOT_NODE = 0
LEFT_CURLY_NAME =  "leftcurly0"
RIGHT_CURLY_NAME = "rightcurly"
UNDERSCORE_NAME =  "underscore"
RANDOMIZE_LISTS = True
FUNCPTR_TABLE_NAME = "ftable"  # name for the global function table
FUNCPTR_INDEX_NAME = "index"
FUNCPTR_VAR_NAME = "fptr"


## helpers
def nx_random_tree(n):
    g = nx.random_tree(n)
    return nx.bfs_tree(g, source=ROOT_NODE)

def save_digraph(g: nx.DiGraph, filepath: str):
    nx.write_edgelist(g, filepath, data=False)  # Saves edges only (no weights or attributes)
    print(f'[*] Saved graph edgelist to {filepath}')

def load_digraph(filepath: str) -> nx.DiGraph:
    return nx.read_edgelist(filepath, create_using=nx.DiGraph())

def count_leaf_nodes(G):
    return sum(1 for n in G.nodes if G.out_degree(n) == 0)


def random_string(length: int) -> str:
    letters = string.ascii_letters  # a-z + A-Z
    return ''.join(random.choices(letters, k=length))

def get_func_prefix() -> str:
    return "func_"

def get_flag_suffix(c: str, length: int) -> str:
    if c in string.ascii_letters + string.digits:
        return c * length
    elif c == '{':
        return LEFT_CURLY_NAME
    elif c == '}':
        return RIGHT_CURLY_NAME
    elif c == '_':
        return UNDERSCORE_NAME
    else:
        raise Exception(f"Can't get flag suffix for {c=}")


## Generating file

def get_deepest_node(g, root) -> int:
    """Return the node id of a node with the maximum depth from root"""
    # Compute shortest paths from root to all reachable nodes
    lengths = nx.single_source_shortest_path_length(g, root)

    # Get the node with the maximum depth (longest path from root)
    deepest_node = max(lengths, key=lengths.get)
    return deepest_node


def pick_unrelated_nodes(g: nx.DiGraph, k: int, max_attempts=100) -> List[int]:
    """Pick k nodes from g such that none are an ancestor of one another"""
    nodes = list(g.nodes())

    for attempt in range(max_attempts):
        selected = []
        excluded_ancestors = set()

        # starting with the deepest node should remove some of the bad choices
        deepest = get_deepest_node(g, ROOT_NODE)
        selected.append(deepest)
        excluded_ancestors.update(nx.ancestors(g, deepest))

        random.shuffle(nodes)

        for node in nodes:
            if node not in excluded_ancestors and node not in selected:
                selected.append(node)
                excluded_ancestors.update(nx.ancestors(g, node))
                if len(selected) == k:
                    print(f'  DBG: pick_unrelated_nodes succeeded on {attempt}-th try')
                    return selected

    raise RuntimeError(f"Unable to find {k} ancestor-independent nodes after {max_attempts} attempts.")


def pick_leaf_nodes(g: nx.DiGraph, k: int) -> List[int]:
    """Return a list of k leaf nodes"""
    # Identify leaf nodes (nodes with out-degree 0)
    leaves = [node for node in g.nodes if g.out_degree(node) == 0]

    if len(leaves) < k:
        raise ValueError(f"Only {len(leaves)} leaf nodes available, but {k} requested.")

    return random.sample(leaves, k)


def pick_random_name(length: int):
    return get_func_prefix() + random_string(length)


def get_flag_name(c: str, length: int):
    return get_func_prefix() + get_flag_suffix(c, length)


def is_flag_func(name: str) -> bool:
    suffix = name.split('_')[1]
    # special chars
    if suffix in [LEFT_CURLY_NAME, RIGHT_CURLY_NAME, UNDERSCORE_NAME]:
        return True
    # else all the same
    if len(set(suffix)) == 1:
        return True
    return False


def flag_func_to_char(name: str) -> str:
    suffix = name.split('_')[1]
    special_names = {
        LEFT_CURLY_NAME: '{',
        RIGHT_CURLY_NAME: '}',
        UNDERSCORE_NAME: '_'
    }
    # special chars
    if suffix in special_names:
        return special_names[suffix]
    # else all the same
    if len(set(suffix)) == 1:
        return suffix[0]

    raise Exception(f'Could not translate flag func name: {name=}')


def sort_nodes_by_traversal_order(G: nx.DiGraph, nodes: List[int], root: int) -> List[int]:
    # traversal_order = list(nx.bfs_tree(G, root))
    # this is call order
    traversal_order = list(nx.dfs_preorder_nodes(G, root))
    node_set = set(nodes)
    return [n for n in traversal_order if n in node_set]


### PYTHON GENERATION


def write_py_function_defs(g: nx.DiGraph, func_names: Dict[int, str]) -> List[str]:
    """Return a list of function bodies"""

    function_defs = []
    names_defined = set()

    for n in g.nodes:
        cur_name = func_names[n]
        # repeat characters in flag would cause this
        if cur_name in names_defined:
            continue

        # for debug, print the flag
        if is_flag_func(cur_name):
            flag_char = flag_func_to_char(cur_name)
            print_line = f'    print("{flag_char}", end="")\n'
        else:
            print_line = ''

        # add calls to each of the child nodes
        if len(list(g.successors(n))) > 0:
            child_names = [
                f'{func_names[child_node]}()'
                for child_node in g.successors(n)
            ]
            calls = "    " + "\n    ".join(child_names)
        else:
            calls = "    return"

        names_defined.add(cur_name)

        # Fill in the current function definition & body
        cur_def = f"""
def {cur_name}():
{print_line}{calls}
"""
        # End: cur_def

        function_defs.append(cur_def)

    return function_defs


def fill_out_python_template(g: nx.DiGraph, function_names: Dict[int, str]) -> str:
    # Get the function bodies
    function_defs = write_py_function_defs(g, function_names)
    all_functions = "\n\n".join(function_defs)

    # Get the main function
    root_func = function_names[ROOT_NODE]
    main_body =   "def main():\n"
    main_body += f"    {root_func}()\n"
    main_body +=  '    print("")  # just print a newline\n'

    # Fill in the template
    script = f"""
{all_functions}

{main_body}

if __name__ == "__main__":
    main()
"""
    # End: template

    return script



#### C GENERATION


def generate_c_expression_sequence(
        varname: str,
        initial_val: int,
        x: int,
        count: int=5
    ):
    """Yield a sequence of expressions that results in the varname being set to x"""

    if count < 3:
        raise ValueError("Count must be at least 3 (init, middle ops, final adjust)")

    expressions = []
    ops = ['+', '-', '^', '&', '|', '*']

    # Step 1: Initialize varname with a random unsigned int
    # expressions.append(f"{varname} = {initial_val};")
    dbg_expr = f"// {varname} = {hex(initial_val)} ({initial_val})"
    expressions.append(dbg_expr)

    current_value = initial_val

    # Step 2: Perform (count - 2) random operations on varname
    for _ in range(count - 2):
        op = random.choice(ops)
        if op == '*':
            operand = random.randint(2, 15)
        else:
            operand = random.randint(0, 0xFF)

        expr = f"{varname} = {varname} {op} {operand};"
        expressions.append(expr)

        # Simulate operation to track value
        if op == '+':
            current_value = (current_value + operand) & 0xFFFFFFFF
        elif op == '-':
            current_value = (current_value - operand) & 0xFFFFFFFF
        elif op == '^':
            current_value ^= operand
        elif op == '&':
            current_value &= operand
        elif op == '|':
            current_value |= operand
        elif op == '*':
            current_value = (current_value * operand) & 0xFFFFFFFF

        dbg_expr = f"// {varname}={hex(current_value)} ({current_value})"
        expressions.append(dbg_expr)

    # Step 3: Final adjustment to make varname equal to x
    diff = (x - current_value) & 0xFFFFFFFF
    # Use '+' or '-' based on diff size
    if diff <= 0x7FFFFFFF:
        expressions.append(f"{varname} = {varname} + {diff};")
    else:
        # It's actually a negative diff, do subtraction
        diff = (0x100000000 - diff)
        expressions.append(f"{varname} = {varname} - {diff};")

    dbg_expr = f"// {varname} = {x};"
    expressions.append(dbg_expr)

    return expressions


def get_c_call(
    callee_name: str,
    callee_lookup_index: int,
    incoming_iv: int,
    callee_initial_value: int,
) -> Tuple[str, int]:
    """Produce a call to the given function, returning call and outgoing index value"""

    # call = f'{callee_name}();'

    # assign table index index
    # call =  f'    {FUNCPTR_INDEX_NAME} = {table_index};\n'
    # ... in a complicated way
    arithmetic_exprs = generate_c_expression_sequence(FUNCPTR_INDEX_NAME, incoming_iv, callee_lookup_index)
    random_ops = '    ' + '\n    '.join(arithmetic_exprs) + '\n'
    call = random_ops

    call += f'    {FUNCPTR_VAR_NAME} = {FUNCPTR_TABLE_NAME}[{FUNCPTR_INDEX_NAME}];\n'

    call += f'    {FUNCPTR_VAR_NAME}({callee_initial_value});\n'
    # For debugging purposes, add a comment to show intended target and values
    call += f'    // call {callee_name}();\n'
    call += f'    // index = {callee_lookup_index};\n'

    return call, callee_lookup_index


def write_c_function_defs(
    g: nx.DiGraph,
    func_names: Dict[int, str],
    name_to_lookup_index: Dict[str, int],
    in_values: Dict[str, int],
) -> List[str]:
    """Return a list of function bodies written in C"""

    function_defs = []
    names_defined = set()

    node_list = list(g.nodes)[:]
    if RANDOMIZE_LISTS:
        random.shuffle(node_list)

    for n in node_list:
        cur_name = func_names[n]
        # repeat characters in flag would cause this
        if cur_name in names_defined:
            continue

        # for debug, print the flag
        if is_flag_func(cur_name):
            flag_char = flag_func_to_char(cur_name)
            print_line = f'#ifdef DEBUG\n    printf("{flag_char}");\n#endif\n'
        else:
            print_line = ''

        # add calls to each of the child nodes
        if len(list(g.successors(n))) > 0:

            # Set this for parent, and track it as it changes across calls
            caller_iv = in_values[cur_name]
            child_invocations = []
            for child_node in g.successors(n):
                child_name = func_names[child_node]
                child_table_index = name_to_lookup_index[child_name]
                child_iv = in_values[child_name]

                cur_call, new_iv = get_c_call(
                    child_name,
                    child_table_index,
                    caller_iv,
                    child_iv,
                )

                child_invocations.append(cur_call)
                caller_iv = new_iv

            calls = f"    void (*{FUNCPTR_VAR_NAME})(int);\n"
            calls +=  "\n    ".join(child_invocations)
        else:
            calls = ""

        names_defined.add(cur_name)

        # Fill in the current function definition & body
        cur_def =  f"void {cur_name} (int {FUNCPTR_INDEX_NAME}) " + "{\n"
        cur_def += print_line
        cur_def += calls
        cur_def += "}\n"

        function_defs.append(cur_def)

    return function_defs


def fill_out_c_template(g: nx.DiGraph, function_names: Dict[int, str]) -> str:
    """Produce a compilable C file from the graph and names"""

    # libs
    includes = ["stdio.h"]
    all_includes = "\n".join(f"#include <{name}>" for name in includes) + "\n"

    # Must forward declare functions to avoid ordering nonsense
    # randomize this list
    prototype_function_list = list(function_names.values())[:]
    if RANDOMIZE_LISTS:
        random.shuffle(prototype_function_list)
    function_decls = [f"void {name}(int);" for name in prototype_function_list]
    all_decls = "\n".join(function_decls) + "\n"

    # generate static 32-bit integers for each function to pass into each func
    in_values: Dict[str, int] = {
        func_name: random.randint(0, 0xFFFFF)
        for func_name in function_names.values()
    }

    # Make the function call table (using each name only once)
    call_function_list = list(set(function_names.values()))[:]
    if RANDOMIZE_LISTS:
        random.shuffle(call_function_list)
    # Make func_name to table index mapping for later lookups
    function_table_dict: Dict[str, int] = {
        name: i
        for i, name in enumerate(call_function_list)
    }
    # Make the string defining the lookup table
    #void (*function_table[4])(int) = { func0, func1, func2, func3 };
    num_funcs = len(call_function_list)
    func_ptr_table = f"void (*{FUNCPTR_TABLE_NAME}[{num_funcs}])(int) = "
    func_ptr_table += "{ " + ", ".join(call_function_list) + " };\n"


    # Get the function bodies
    function_defs = write_c_function_defs(
        g,
        function_names,
        function_table_dict,
        in_values
    )
    all_functions = "\n\n".join(function_defs)


    # Get the main function
    root_func_name = function_names[ROOT_NODE]
    roots_initial_value = in_values[root_func_name]
    main_body =  "int main(int argc, char** argv) {\n"
    main_body +=f"    {root_func_name}({roots_initial_value});\n"
    main_body += '#ifdef DEBUG\n'
    main_body += '    printf("\\n");\n'
    main_body += '#endif\n'
    main_body += "    return 0;\n"
    main_body += "}\n"

    # Fill in the template
    source = "\n\n".join([
        all_includes,
        all_decls,
        func_ptr_table,
        all_functions,
        main_body,
    ])

    return source


#### GRAPH TO CODE


def convert_graph_to_script(g: nx.DiGraph, flag: str, lang: str = "py") -> str:
    """Take the graph and the flag and emit a python script that would print the flag"""

    # generate random names for all nodes
    SUFFIX_LEN = 10  # len("rightcurly") = 10
    function_names = {
        n: pick_random_name(SUFFIX_LEN)
        for n in range(len(g.nodes))
    }

    # now override those function names for each letter in the flag
    num_flag_chars = len(flag)
    # pick functions that don't call each other to ensure a traversal prints
    # unrelated_nodes = pick_unrelated_nodes(g, num_flag_chars)
    unrelated_nodes = pick_leaf_nodes(g, num_flag_chars)

    # sort them in traversal order so the flag is spelled out when they execute
    sorted_unrelated_nodes = sort_nodes_by_traversal_order(g, unrelated_nodes, ROOT_NODE)

    for i, cur_char in enumerate(flag):
        cur_node = sorted_unrelated_nodes[i]
        function_names[cur_node] = get_flag_name(cur_char, SUFFIX_LEN)

    if lang == "py":
        source = fill_out_python_template(g, function_names)
    elif lang == "c":
        source = fill_out_c_template(g, function_names)
    else:
        raise Exception(f"Unexpected {lang=}")

    return source


#### MAIN



def generate_challenge(
    password: str,
    output_path: Optional[Path] = None,
    password_output_path: Optional[Path] = None,
):
    """Generate a random tree, then make it into a binary that takes the flag"""

    # min_nodes = 15
    # min_nodes = 100
    # min_nodes = 1_000
    min_nodes = 10_000  # takes ~3 seconds to build
    # min_nodes = 100_000  # takes ~35 seconds to build

    start_time = time.time()
    g = nx_random_tree(min_nodes)
    duration = time.time() - start_time

    # Debug stats
    num_nodes = len(g.nodes)
    num_edges = len(g.edges)
    # Compute max depth using BFS
    lengths = nx.single_source_shortest_path_length(g, ROOT_NODE)
    out_max_depth = max(lengths.values())
    # Compute max out-degree
    out_max_way = max(dict(g.out_degree()).values())
    print(f'[*] Generated graph in {duration:.02f} seconds:')
    print(f'  {num_nodes} nodes, {num_edges} edges, {out_max_depth=}, {out_max_way=}')

    # Save the graph
    extra_dir = Path('debug')
    if not extra_dir.exists():
        extra_dir.mkdir(parents=True, exist_ok=True)

    filename = f"graph_{num_nodes}_{out_max_depth}_{out_max_way}"

    # out_graph = extra_dir.joinpath(filename + '.edgelist')
    # save_digraph(g, out_graph)

    # lang = "py"
    lang = "c"
    script = convert_graph_to_script(g, password, lang)

    out_source_file = extra_dir.joinpath(filename + f'.{lang}')
    with open(out_source_file, 'w') as f:
        f.write(script)

    if out_source_file.exists():
        print(f"[*] Wrote source to {out_source_file} ({out_source_file.stat().st_size} bytes)")
    else:
        print(f"[!] Failed to write source to {out_source_file}, check output for details")
        exit(-1)

    # Give the file write time to finish
    time.sleep(0.05)

    # Test script
    if lang == "py":
        cmd = f"python3 {str(out_source_file)}"
        print(f'Running script via: "{cmd}"...')
        output = subprocess.check_output(cmd.split())

        if password in output.decode():
            print(f'\n[+] Flag found in output, good to go\n')
        else:
            print(f'\n\n[-] Flag NOT found in output')
            print(f"{output=}")
            exit(-1)

    # Compile and test binary
    if lang == "c":
        if output_path is None:
            release_dir = Path('samples')
            release_dir.mkdir(exist_ok=True)
            output_path = release_dir.joinpath(filename)

        debug_bin = extra_dir.joinpath(filename).with_suffix('.debug')

        ## Build and test debug
        #defines_for_debug = "-DDEBUG=1"
        #cc = 'gcc'
        ##cc = 'clang'  # clang can't hang
        ## cmd = f"{cc} {str(out_source_file)} -g -o {debug_bin} {defines_for_debug}"
        #cmd = f"{cc} {str(out_source_file)} -o {debug_bin} {defines_for_debug}"  # faster without -g
        #print(f'[C] Compiling debug binary: "{cmd}"')

        #start_time = time.time()
        #subprocess.check_call(cmd.split())
        #duration = time.time() - start_time

        #if debug_bin.exists():
        #    print(f'[*] Compiled debug binary in {duration:.01f} seconds to {debug_bin}')
        #else:
        #    print(f'[!] Failed to compile debug binary, check output!')
        #    exit(-1)

        ## run binary to double check the flag worked
        #cmd = f"{debug_bin.resolve()}"
        #print(f'[R] Running debug binary: "{cmd}"...')
        #start_time = time.time()
        #output = subprocess.check_output(cmd.split())
        #duration = time.time() - start_time
        #print(f'[*] Debug binary ran in {duration:.02f} seconds')
        ## check the flag was printed
        #if password in output.decode():
        #    print(f'[+] Flag found in debug output, good to go')
        #else:
        #    print(f'[-] Flag NOT found in output, will not produce release binary')
        #    print(f"{output=}")
        #    exit(-1)

        # write flag used to another dir
        if password_output_path is None:
            flag_dir = Path("flags")
            flag_dir.mkdir(exist_ok=True)
            password_output_path = flag_dir.joinpath(filename)
        with open(password_output_path, 'w') as f:
            f.write(password)

        if password_output_path.exists():
            print(f'[*] Wrote flag used to {password_output_path}')

        # No debug flags or release flags
        cc = 'gcc'
        cmd = f"{cc} {str(out_source_file)} -o {output_path}"
        print(f'[C] Compiling release binary: "{cmd}"')
        start_time = time.time()
        subprocess.check_call(cmd.split())
        duration = time.time() - start_time

        if output_path.exists():
            print(f'[*] Compiled release binary in {duration:.01f} seconds to {output_path}')

            # rm the extra stuff to save space (C files are ~42MB, binaries are ~19MB)
            print(f'[*] Removing debug build and source...')
            debug_bin.unlink(missing_ok=True)
            out_source_file.unlink(missing_ok=True)
            if list(extra_dir.iterdir()) == []:
                extra_dir.rmdir()

            print(f'\n[+] This one is ready for release: {output_path}')
        else:
            print(f'\n[-] Failed to compile binary, check output!')
            exit(-1)


def main() -> int:

    parser = argparse.ArgumentParser()

    # For generating a single special binary
    if os.getenv("OVERRIDE") == "1":
        print(f"[*] Override mode")
        parser.add_argument("--override-password", required=False)
        parser.add_argument("--override-dir", required=False)

        args = parser.parse_args()

        override_dir = Path(args.override_dir)
        challenge_password = args.override_password

        challenge_path = override_dir / "samples"   / "challenge_0"
        password_path  = override_dir / "passwords" / "challenge_0"

        challenge_path.parent.mkdir(parents=True, exist_ok=True)
        password_path.parent.mkdir(parents=True, exist_ok=True)

        generate_challenge(args.override_password, challenge_path, password_path)
        print(f'Generated challenge "{challenge_path}" with password "{challenge_password}"')

        return 0

    # Normal operation
    parser.add_argument("--seed-hex", required=True)
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--password-directory", required=True)
    parser.add_argument("--num-challenges", type=int, required=True)

    args = parser.parse_args()

    seed = bytes.fromhex(args.seed_hex)

    for challenge_idx in range(args.num_challenges):
        challenge_seed = hmac.digest(seed, f"{challenge_idx}".encode(), 'sha256')
        challenge_password = "PASS{" + challenge_seed.hex()[:16] + "}"

        challenge_path = Path(args.output_directory) / f"challenge_{challenge_idx}"
        challenge_path.parent.mkdir(parents=True, exist_ok=True)

        password_path = Path(args.password_directory) / f"challenge_{challenge_idx}"
        password_path.parent.mkdir(parents=True, exist_ok=True)

        generate_challenge(challenge_password, challenge_path, password_path)
        print(f'{challenge_idx}. Generated challenge "{challenge_path}" with password "{challenge_password}"')

    return 0


if __name__ == '__main__':
    main()
