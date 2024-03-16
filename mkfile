all:V:
	go build .

fmt:V:
	go fmt .

test:V:
	go test -v .

testcov:V:
	go test -v -coverprofile=c.out .

vet:V:
	go vet .
