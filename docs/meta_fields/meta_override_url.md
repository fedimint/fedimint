# `meta_override_url`

A URL to a file containing overrides for meta fields. Currently, changing meta fields on the fly is not supported and
doing so manually is very error-prone. Until this is fixed we need a way to quickly change meta fields, which is
accomplished by adding a layer of indirection here.

Since the file will be served by a single web server the security guarantees provided are much lower. This field should
only be used for testing purposes and will be discontinued in the future.

## Structure

The field's value itself is an HTTPS URL pointing to a JSON file containing the overrides. The file has the following
structure:

```json
{
	"<hex_federation_id>": {
		"<meta_field_name>": "<meta_field_value>",
        …
	}
}
```

Including the federation id in the file allows serving the same file for multiple federations and also prevents
accidental re-use.
