.PHONY: runner install clean

# Build the Go tool execution runner.
# Requires: brew install go
runner:
	cd tools-runner && go build -o ../recon-runner .
	@echo "Built: ./recon-runner"

# Install runner binary to PATH.
install: runner
	cp recon-runner /usr/local/bin/recon-runner
	@echo "Installed: /usr/local/bin/recon-runner"

# Install Python dependencies.
deps:
	python3 -m pip install -r requirements.txt

clean:
	rm -f recon-runner tools-runner/recon-runner
