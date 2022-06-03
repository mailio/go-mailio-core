.PHONY: test
test: 
	find . -name go.mod -execdir go test ./... \;
