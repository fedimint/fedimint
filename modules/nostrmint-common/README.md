# nostrmint

Since the npub is for the fedimint itself, we limit nostr interaction to authenticated guardians `export FM_PASSWORD=pass`

You can list message requests: `fedimint-cli nostr list-note-requests`

You can create note requests:

```sh
FM_OUR_ID=0 fedimint-cli nostr text-note --content "nostrmint doing nostrmint things"
```

This will give you an event ID, this is the hex id of the event created and submitted to be signed. In a dev environment you can set `FM_OUR_ID` to other Peer Ids to sign. Once a threshold is met, the event is broadcast.

```sh
FM_OUR_ID=1 fedimint-cli nostr sign-note --event-id b9c4f093b08580ca73c68894f5207d5f1a63002b8ab3452ab85ffec149861533
FM_OUR_ID=2 fedimint-cli nostr sign-note --event-id b9c4f093b08580ca73c68894f5207d5f1a63002b8ab3452ab85ffec149861533
```

In a devimint shell (tmuxinator or mprocs) all passwords are the same so you only need to do it once

```sh
export FM_PASSWORD=pass
```

You can get the npub of the federation: `fedimint-cli get-npub`

Once an event is signed by a threshold quorum, navigate to coracle.social or another client and you should see the note.