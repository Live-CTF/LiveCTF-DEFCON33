
default: program

main.o: main.c
	gcc -c -Wall -Wpedantic -o $@ $^

checker.c: generate.py
	python generate.py > $@

checker.S: checker.c
	gcc -ffunction-sections -fno-asynchronous-unwind-tables -ffixed-rbx -S -Wall -Wpedantic -o $@ $^

checker-obf.S: checker.S obfuscate.py
	python obfuscate.py < $< > $@

checker.o: checker-obf.S
	as -o $@ $^

program: checker.o main.o
	gcc -s -o $@ $^

program-plain: checker.c main.c
	gcc -Wall -Wpedantic -o $@ $^

clean:
	rm -f *.S program program-plain

.PHONY: default clean
