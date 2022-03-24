test:
	go vet ./...
	go test ./...

release: test
ifdef VERSION
	-git branch ${VERSION}
	git checkout ${VERSION}
	@perl -i -pe 's/Version = "v[0-9]+.[0-9]+.[0-9]+"/Version = "${VERSION}"/g' internal/workos/workos.go
	git add internal/workos/workos.go
	-git commit -m ${VERSION}
	git push --set-upstream origin ${VERSION}
	open https://github.com/workos/workos-go/compare/${VERSION}?expand=1

else
	@echo "\033[91mVERSION is not defided\033[00m"
	@echo "~> make VERSION=\033[90mv0.0.0\033[00m release"
endif
