# Contributing

We're looking forward to code contributions.

Here's a brief list of areas where contributions are particularly welcome:
- adding support for a new LN implementation
- maintaining the existing LN implementation support
- extending the interface with new features
- security testing
- finding and fixing bugs

To get started, please consider the following:
- first discuss the change via issue, email or any other method
  with the project owners
- follow our [coding guidelines](/doc/coding_guidelines.md) when developing


## Testing

Lighter has a unit test suite made with the
[`unittest`](https://docs.python.org/3.5/library/unittest.html) framework.

To run the tests, using docker, run:

```
$ ./unix_helper.sh test
```


## Linting

To check the code for common errors, using docker, run:

```
$ ./unix_helper.sh lint
```

This will check the code with pycodestyle and pylint.
Results of linting procedure are output in the `reports` directory.


## Merge Request Process

1. Rebase on develop for new features or master for fixes

1. Test and lint the code to make sure there are no regressions

1. Update the README.md with details about the introduced changes

1. Create the merge request


## Code of Conduct

This project adheres to No Code of Conduct.  We are all adults.  We accept anyone's contributions.  Nothing else matters.

For more information please visit the [No Code of Conduct](https://github.com/domgetter/NCoC) homepage.
