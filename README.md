# Google Tag Manager 'PII - URL Cleaner' Server Variable Template

![Repo Size](https://img.shields.io/github/repo-size/justia/gtm-pii-url-cleaner-server-variable) ![License](https://img.shields.io/github/license/justia/gtm-pii-url-cleaner-server-variable)

---

## Summary

This repository contains a [Google Tag Manager Server Variable template](https://developers.google.com/tag-manager/templates) that makes it possible to clean up URLs to remove any personally identifiable information (PII) before sending them to analytics or third-party platforms.

## Options

### URL
A URL from event data **{{ED - Page Location}}** (event_data.page_location).

### Query Parameter Keys
List the query parameter keys to redact, delete or mask. You can use different matching condition options.

### Query Parameter Values
Query parameter values with dynamic or unknown keys can be redacted if the value matches a specified regular expression.

## Examples
<img src="images/example1.png" width=400>

## Tips
Make sure to default the `false` value to the initial input, in case any error happens during the replacement of the URL.

## Contributing
See our [contributing guidelines](CONTRIBUTING.md).
