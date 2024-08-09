# Contributing

Welcome to the Fedimint project! We're thrilled that you're interested in contributing to our open-source community. Below are some resources to help you get started:

> Please note that all contributions happen under the MIT license as described at the bottom of this page.

## Getting involved

Here are the recommended steps for new developers:

1. Start by reading our [non-technical primer](https://fedimint.org/docs/intro) and viewing the [videos and articles on the blog](https://fedimint.org/blog)
2. Before writing code you will need to [set up the dev environment](docs/dev-env.md)
3. [Run the dev environment](docs/tutorial.md) to ensure that everything works on your computer
4. Contact @kodylow to get a good first issue matched to your skillset: you can schedule a [call with Kody here](https://cal.com/kody-low-ix8qoa/30min) or just shoot him a DM in our [Developer discord](https://chat.fedimint.org) with your background, skillset, and what you're interested in working on.
5. Now take a look at our [GitHub Issues](https://github.com/fedimint/fedimint/issues) you may want to search for [good first issues](https://github.com/fedimint/fedimint/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22)
6. Join our [Developer calls](https://calendar.google.com/calendar/u/0/embed?src=fedimintcalendar@gmail.com) especially the ones for new contributors

> Small PRs fixing typos, TODOs, broken links are always welcome, but please discuss bigger changes on Discord or GitHub first.

<!-- markdown-link-check-disable -->

For commits, please use [imperative mood](https://stackoverflow.com/questions/3580013/should-i-use-past-or-present-tense-in-git-commit-messages/3580764#3580764).

<!-- markdown-link-check-enable -->

## Areas of Contribution

Below are some broad and general areas of contribution to get you started

- [Fedimint Modules](docs/architecture.md)
- [Fedimint Database System](docs/database.md)
- [The Lightning Gateway](docs/gateway.md)
  - [Developing gateway-lnrpc-extension](docs/gateway.md#developing-gateway-lnrpc-extension)
  - [Developing Gateway UI](https://github.com/fedimint/ui)
- [Fedimint Guardian UI](https://github.com/fedimint/ui)
- [Nix Build System](docs/nix-ci.md)
- [Devimint](devimint/)
- [Scripts](scripts/README.md)

### New Contributors

If you are new to contributing to Fedimint, please come through @kodylow as your point of contact to get a good first issue matched to your skillset. You can schedule a [call with Kody here](https://cal.com/kody-low-ix8qoa/30min) or just shoot him a DM with your background, skillset, and what you're interested in working on.

**Contributing to the core Fedimint repo requires expertise with Rust and distributed systems**. There are a bunch of other projects in and around fedimint like UIs, clients, and other services that are far more approachable, so if you're new to coding/bitcoin/rust please try to start with one of those to get a feel for Fedimint before trying to contribute to the core repo. The hardest part with new contributors is finding a good issue to match your skillset! Again, please go through @kodylow so we can get a good match for you so you can get started.

Once you have an issue you're working on, please post blockers or questions in the [#new-contributors channel](https://discord.gg/BGFMXSkNJW) if you're stuck on something.

There is almost always a simple/fast answer to early contributor problems and we'd like to get you past those as quickly as possible to making valuable contributions.

Things like dev environment issues, build errors, "what does this state machine do", "I don't understand how this contract is structured", etc. Just ask in the #new-contributors channel and someone will get back to you ASAP.

If you have any questions or need assistance, don't hesitate to reach out to us on our [Developer Discord](https://chat.fedimint.org) in the [#new-contributors channel](https://discord.gg/BGFMXSkNJW). Our community is friendly and supportive, and we're here to help you succeed.

Happy Hacking!

# Feature Process

Fedimint is a project with high inherent complexity, maintained by relatively few people and thus needs to avoid accidental complexity through unnecessary requirements. The following process aims to minimize feature creep:

Any changes that cannot be easily reverted because they touch consensus, public APIs, etc. should go through a design phase. For that please open an issue describing:
  * The minimum requirements and why they are necessary
    * Possible additional requirements and why they are useful enough to justify the added complexity
  * The design space you explored
  * The design you consider ideal

Two contributors familiar with the area should ACK before proceeding with an implementation. Feature creep should be avoided both in the design phase as well as when implementing.

## Code/Requirement Ownership
**Please consider yourself personally accountable for the requirements your implementation introduced - you should be able to explain and justify requirements on request.** Some of them might be implicit, especially when introduced by a bug fix and not through the feature process. Please avoid introducing requirements "just in case" and strive for a clean and straightforward design that is easy to maintain and may still be extended at a later point if it becomes necessary. Please try to keep track of your prior work as the project progresses since requirements may have become redundant.

**Furthermore, question existing requirements and consider removing them if nobody can explain well why they exist;** if a removal needs to be reverted it does not mean that you made a mistake, at least now we are aware why it is necessary and can record this in a comment. If you never have to put something back in you are not removing enough code.

Do not optimize code that should not exist in the first place. **Premature optimization is the root of all evil.**

# Code Review Policy

* CI must pass (enforced)
* 1 review is mandatory (enforced), 2 or more ideal
* If you believe your change is simple, and non-controversial enough, and you want
  to avoid merge conflicts, or blocking work before it gets enough reviews, label it with
  `needs further review` label and Merge it.

Feel free to post a link to a PR on #code-review to ask for more code reviews.

The goal of the policy is to strike a balance between good review coverage
and fast iteration time in a globally distributed team consisting of mostly
volunteers with varying levels of availability.

1 mandatory review is meant to enforce basic sanity and security cross-checking.

2 ideal reviews is a target we would like to maintain at the current level of project
maturity.

PRs labeled with `needs further review` label are meant to enable flexible
"code review debt". The label can be removed after further reviews are done.
Regular contributors are encouraged to review PRs even after they were merged.
Furthermore, PRs with `needs further review` will be reviewed during weekly
"Code Review" meetings.


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
