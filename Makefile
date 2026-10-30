.PHONY: test run seed lab native asan security demo native-library

run: native-library
	python3 run.py

seed:
	DOLOS_ALLOW_DEMO_SEED=1 python3 -m dolos.seed

test: native-library
	python3 -m unittest discover -s tests -v

lab:
	python3 -m labs.vulnerable

native:
	$(CC) -g -O0 -Wall -Wextra -o native/vulnerable native/vulnerable.c
	$(CC) -g -O2 -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2 -o native/secure native/secure.c

asan:
	$(CC) -g -O1 -fsanitize=address -fno-omit-frame-pointer -o native/vulnerable native/vulnerable.c

security:
	python3 scripts/sast_gate.py
	python3 scripts/security_gate.py --input scripts/findings-clean.json

demo:
	python3 scripts/demo_requests.py

# Compiled, bounded C validation is used by the real Python event-ingestion path.
native-library:
	$(CC) -O2 -fPIC -shared -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2 -DDOLOS_LIBRARY -o native/libdolos_native.so native/secure.c
