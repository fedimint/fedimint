# nostrmintYou can list message requests: fedimint-cli list-note-requests

You can create note requests: fedimint-cli create-note --msg "My FROST Message" --peer-id 0
That will only work if you've previously set FM_PASSWORD: export FM_PASSWORD=pass
Then you should see the message request pop up using the list command
Then you can use the other guardians to sign: fedimint-cli sign-note --event-id <EVENT_ID> --peer-id 1
That will only work if you have FM_PASSWORD set correctly for peer 1. In tmuxinator all passwords are the same so you only need to do it once

you can get the npub of the federation: fedimint-cli get-npub

Then signin to snort.social or something and you should see the note
Give it a try and let me know if you get it to work. It's really rough right now but it works!


## Running it

## How it works?

## Contributing

## Goals
