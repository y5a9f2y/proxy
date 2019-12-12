.PHONY: default

default: clean
	@mkdir build
	@cd build && cmake .. && make
	@cp build/bin/proxy .

release: default
	@mkdir output
	@cp -R conf ./output/
	@cp proxy ./output/
	@cd output && tar czvf ../output.tar.gz . >/dev/null 2>&1
	@rm -rf output

clean:
	@if [ -d "build" ]; then rm -rf build; fi
	@if [ -f "proxy" ]; then rm proxy; fi
	@if [ -d "output" ]; then rm -rf output; fi
	@if [ -f "output.tar.gz" ]; then rm -rf output.tar.gz; fi
