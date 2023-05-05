# Contributing

Contributions are very welcome, just open an issue or PR if you see something to improve! 

Please note that all contributions happen under the MIT license as described at the bottom of this page.

## Getting involved

Here are the recommended steps for new developers:
1. Start by reading our [non-technical primer](https://fedimint.org/docs/intro) and viewing the [videos and articles on the blog](https://fedimint.org/blog)
2. Before writing code you will need to [set up the dev environment](dev-env.md)
3. [Run the dev environment](dev-running.md) to ensure that everything works on your computer
4. Now take a look at our [GitHub Issues](https://github.com/fedimint/fedimint/issues) you may want to search for [good first issues](https://github.com/fedimint/fedimint/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22)
5. Introduce yourself on our [Developer discord](https://chat.fedimint.org) and ask any questions there
6. Join our [Developer calls](https://calendar.google.com/calendar/u/0/embed?src=fedimintcalendar@gmail.com) especially the ones for new contributors

Small PRs fixing typos, TODOs, broken links are always welcome, but please discuss bigger changes on Discord or GitHub first.

For commits, please use [imperative mood](https://stackoverflow.com/questions/3580013/should-i-use-past-or-present-tense-in-git-commit-messages/3580764#3580764).

Happy hacking!


## Areas of Contribution

Below are some broad and general areas of contribution to get you started

* [Fedimint Modules](./architecture.md)
* [Fedimint Database System](./database.md)
* [The Lightning Gateway](./gateway.md)
    * [Developing gateway-lnrpc-extension](./gateway.md#developing-gateway-lnrpc-extension)
    * [Developing Gateway-UI (aka, Mintgate)](./gateway.md#developing-gateway-ui-aka-mintgate)
* [Fedimint Setup UI](./ui.md)
* [Nix Build System](./nix-ci.md)
* [Integration tests](../integrationtests/README.md)
* [Scripts](../scripts/README.md)

## Developer Certificate of Origin

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```
