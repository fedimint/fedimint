# Contributing

Welcome to the Fedimint project! We're thrilled that you're interested in contributing to our open-source community. Below are some resources to help you get started:

**Note:** All contributions are made under the MIT license, as described at the bottom of this page.

## Table of Contents

- [Getting Involved](#getting-involved)
- [Areas of Contribution](#areas-of-contribution)
- [Code Review Policy](#code-review-policy)
- [Developer Certificate of Origin](#developer-certificate-of-origin)

## Getting Involved

Here are the recommended steps for new developers:

1. **Learn the Basics**: Start by reading our [non-technical primer](https://fedimint.org/docs/intro) and exploring the [videos and articles on our blog](https://fedimint.org/blog).
2. **Set Up Your Development Environment**: Follow our [dev environment setup guide](docs/dev-env.md) to install the necessary tools.
3. **Run the Development Environment**: Use [this tutorial](docs/tutorial.md) to launch the development environment and ensure everything works correctly on your machine.
4. **Find Your First Issue**:
   - Contact @kodylow to get a good first issue matched to your skillset. You can schedule a [call with Kody here](https://cal.com/kody-low-ix8qoa/30min) or send him a direct message in our [Developer Discord](https://chat.fedimint.org) with your background, skillset, and areas of interest.
   - Browse our [GitHub Issues](https://github.com/fedimint/fedimint/issues) and filter by [good first issues](https://github.com/fedimint/fedimint/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22).
5. **Join Developer Calls**: Participate in our [Developer Calls](https://calendar.google.com/calendar/u/0/embed?src=fedimintcalendar@gmail.com), especially our Weekly Dev Calls every Monday.

Small PRs fixing typos, TODOs, or broken links are always welcome. Please discuss larger changes on Discord or GitHub before proceeding.

<!-- markdown-link-check-disable -->

For commit messages, please use the [imperative mood](https://stackoverflow.com/questions/3580013/should-i-use-past-or-present-tense-in-git-commit-messages/3580764#3580764).

<!-- markdown-link-check-enable -->

**Note:** Contributing to the core Fedimint repo requires expertise in Rust and distributed systems. If you're new to coding, Bitcoin, or Rust, consider starting with our more approachable projects like UIs, clients, or other services to familiarize yourself with Fedimint before tackling the core repo. Finding a good issue that matches your skillset is crucial—please reach out to @kodylow to ensure a smooth start.

Once you've found an issue to work on, please post any blockers or questions in the [#new-contributors](https://discord.gg/BGFMXSkNJW) channel on Discord. There are almost always fast and simple answers to early contributor problems. We're here to help you overcome those challenges quickly so you can make valuable contributions.

Happy Hacking!

## Areas of Contribution

Below are some broad and general areas where you can contribute:

- [Fedimint Modules](docs/architecture.md)
- [Fedimint Database System](docs/database.md)
- [Fedimint Lightning Gateway](docs/gateway.md)
- [Fedimint Guardian & Lightning Gateway UI](https://github.com/fedimint/ui)
- [Nix Build System](docs/nix-ci.md)
- [Devimint](devimint/)
- [Scripts](scripts/README.md)

## Code Review Policy

**Objective:** We aim to balance thorough code reviews with fast iteration, accommodating our globally distributed team of mostly volunteers with varying availability.

- **Continuous Integration (CI):** All PRs must pass CI checks before merging. CI ensures your code doesn't break existing functionality and adheres to our quality standards.
- **Mandatory Reviews:** Each PR requires at least **one** approved review. We recommend having **two or more** reviewers. However, for minor changes such as fixing typos or correcting broken links, one review is acceptable.
- **Labeling for Further Review:** If a PR contains simple or non-controversial changes and you'd like to avoid merge conflicts or unblock subsequent work, label it with the `needs further review` label and merge it. PRs with this label will be discussed during our weekly "Code Review" meetings.

Contributors are encouraged to review PRs even after they have been merged.

If you need additional reviews, feel free to post a link to your PR in the #code-review channel on Discord.

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
