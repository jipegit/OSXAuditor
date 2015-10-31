# Contribution Guide

This page describes how to contribute changes to OSXAuditor.

Please do **not** create a pull request without reading this guide first. Failure to do so may result in the **rejection** of the pull request.

## Philosophy
Here are some core ideas to keep in mind for contributing to OSXAuditor

* At it's core OSXAuditor must be as handy as possible for the Responder.
* OSXAuditor is most effective and helpful if it can run on a stock system without installing any additional tools.
* Must work properly on either live or dead os x system (ie. hard drive copy).
* All output must go through the printandlog() function so that people can add new output format easily.
* All the hashes go into the global hash db.

## Submitting to OSXAuditor

### Submitting Issues
[Issues](https://github.com/jipegit/OSXAuditor/issues) are helpful if you're experiencing issues or want to suggest a feature (code is even better though). Please make sure you provide as much detail as possible including stack traces, screenshots, and code samples.

### Submitting Code
If your changes need to be modified due to some reviews, it is less clutter to tweak an isolated feature branch and push it again.

We welcome pull requests. Here's a quick guide:

1. Fork the repo.

2. Create a feature branch.

3. Build.

4. Push to your fork and submit a pull request.

At this point you're waiting on us. We like to at least comment on, if not accept, pull requests within three business days (and, typically, one business day). We may suggest some changes or improvements or alternatives.

Some things that will increase the chance that your pull request is accepted,:

* Use Python idioms and helpers
* Update the documentation, the surrounding one, examples elsewhere, guides, whatever is affected by your contribution

### Syntax

* Four spaces, no tabs.
* No trailing whitespace.
* Prefer &&/|| over and/or.
* a = b and not a=b.
* Follow the conventions you see used in the source already.
* When in doubt default to [PEP 8 -- Style Guide for Python Code](http://legacy.python.org/dev/peps/pep-0008/).
