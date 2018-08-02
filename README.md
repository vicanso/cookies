# cookies

[![Build Status](https://img.shields.io/travis/vicanso/cookies.svg?label=linux+build)](https://travis-ci.org/vicanso/cookies)

Signed and unsigned cookies based on Keygrip. It derives from [pillarjs/cookies](https://github.com/pillarjs/cookies).


## test

go test -race -coverprofile=test.out ./... && go tool cover --html=test.out

### bench

go test -v -bench=".*" ./