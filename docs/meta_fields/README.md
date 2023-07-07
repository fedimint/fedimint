# Meta Fields

Federations can supply additional config and metadata to clients. While these meta fields are not interpreted by
Fedimint, they are consensus relevant, i.e. they cannot differ between federation members. This way clients can rely on
their correctness.

The following meta fields have been defined as part of the core Fedimint protocol:

* [`federation_expiry_timestamp`](federation_expiry_timestamp.md): A timestamp after which the federation will shut down
* [`federation_name`](federation_name.md): The human-readable name of the federation
* [`meta_override_url`](meta_override_url.md): A URL to a file containing overrides for meta fields (will be deprecated in the future)
* [`welcome_message`](welcome_message.md): A welcome message for new users joining the federation

## Defining new meta fields
To define a new meta field:

* Create the definition file `meta_fields/<name_of_meta_field>.md`
  * The field name should be snake_case and used as the title of the document
  * The first section should contain a high-level description of the meta field
  * Lastly, the structure and semantics of the meta field should be described in detail. If the value is JSON encoded,
    the JSON structure should be described too.
* Add a link to the document in the list above in alphabetical order
* Open a PR with these changes

## Third party extensions
Third party apps may define their own meta fields. Please use the following naming convention for keys:
`<app_name>:<field_name>`. This will ensure that the introduction of new official meta fields will not cause conflicts
with existing applications.

If widely adopted these may become standardised in the future, so the definitions of third party extensions should
follow the same structure as described above. Below we list known third party extensions (please open a PR to add
yours):

*None yet*
