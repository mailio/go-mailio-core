# Contributing

1. [Install Go](https://golang.org/doc/install).
1. Clone the repo:

   `git clone https://github.com/mailio/go-mailio-core`

1. Change into the checked out source:

   `cd go-mailio-core`

1. Fork the repo.
1. Set your fork as a remote:

   `git remote add fork https://github.com/GITHUB_USERNAME/go-mailio-core.git`

1. Make changes (see [Formatting](#formatting) and [Style](#style)) and commit
   to your fork. Initial commit messages should follow the
   [Conventional Commits](https://www.conventionalcommits.org/) style (e.g.
   `feat(functions): add gophers codelab`).
1. Send a pull request with your changes.
1. A maintainer will review the pull request and make comments. Prefer adding
   additional commits over amending and force-pushing since it can be difficult
   to follow code reviews when the commit history changes.

   Commits will be squashed when they're merged.

# Formatting

All code must be formatted with `gofmt` (with the latest Go version) and pass
`go vet`.

# Style

Please read and follow https://github.com/golang/go/wiki/CodeReviewComments for
all Go code in this repo.

The following style guidelines are specific to writing Go samples.
