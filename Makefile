.PHONY: default

default: clean
	@mkdir build
	@cd build && cmake .. && make
	@cp build/bin/proxy .

clean:
	@if [ -d "build" ]; then rm -rf build; fi
	@if [ -f "proxy" ]; then rm proxy; fi
