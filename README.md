# Security Advisory Alert

Checks once a day whether the packages installed by Composer are affected by a
published security advisory, or by an announced upcoming Drupal security
release (PSA), and emails an alert.

The package list is read from **`vendor/composer/installed.json`, not from
`composer.lock`** (see [Package list](#package-list-installedjson-not-composerlock)).

It works on a single site and on a multisite, with nothing to configure for
either (see [Single site and multisite](#single-site-and-multisite)).

## Single site and multisite

The check is about the code, so it runs **once per codebase** (one `vendor/`),
whatever the number of sites using it.

**Single site.** The site's cron runs the check once a day and sends one
email when something is found.

**Multisite.** All the sites share the same `vendor/` and the same
filesystem, but each has its own database and cron. The first site whose cron
runs does the check and sends the email; the other sites of the same codebase
see that it was done and skip it (or reuse the result). So there is still
**one** check and **one** email a day, not one per site. Each site's settings
page shows the same "Last audit" line, with the name of the site that ran it.

Both modes use the same mechanism: a lock, a cache and the last result stored
on disk (see [File storage](#file-storage)), since the database is not shared
between the sites of a multisite. With a single site it simply has one user.

The configuration (recipients, severities) is per site, like any config. In a
multisite sharing `conf/` it is the same for all sites; the email is sent with
the configuration of the site that runs the check.

## What is checked

| Source | What | How |
|---|---|---|
| [OSV](https://osv.dev) | Published advisories for every installed package (`vendor/composer/installed.json`, so dev packages only if installed), incl. drupal.org SAs and GitHub advisories | `api.osv.dev` querybatch + details |
| drupal.org Composer advisory API | Risk label of Drupal SAs (OSV has none) | `packages.drupal.org/8/security-advisories` |
| Package repository | Latest stable version, to suggest an upgrade | packagist.org or packages.drupal.org, as recorded by Composer |
| drupal.org PSA feed | Announced upcoming security releases for projects in the codebase | Core's `system.sa_fetcher` (`updates.drupal.org/psa.json`) |

Severity (critical / high / medium / low / unknown) comes from, in order: the
source database label (GitHub), the CVSS v3/v4 vector, the drupal.org SA risk
label ("Moderately critical" = high...), keywords of the description.

Pre-release versions are also checked against their base version
(`6.3.0-beta2` as `6.3.0`), as Composer does and OSV does not.

No `composer` binary is needed on the server.

## Package list: installed.json, not composer.lock

The module reads **`vendor/composer/installed.json`**. It does **not** read
`composer.lock`, which does not need to be deployed.

| | `composer.lock` | `vendor/composer/installed.json` (used) |
|---|---|---|
| Describes | what *should* be installed | what *is* installed in this `vendor/` |
| Written by | `composer update` / `require` | `composer install` / `update` |
| Deployed | only if the build ships it | always, with `vendor/` |
| Dev packages | always listed | only if installed (not with `--no-dev`) |

Why:

- It describes the code that actually runs, which is what a security alert is
  about. On a `--no-dev` build, dev tools that are not deployed are not
  reported.
- It is always present where the site runs (no `vendor/`, no Drupal), whatever
  the build puts in the archive.
- It is what `composer audit` checks by default (`--locked` is needed to audit
  `composer.lock`).

When `vendor/` was installed from the lock (the normal case), both files list
the same packages, versions and repositories.

The file is located through the site's own Composer autoloader (service
`class_loader`), so the right `vendor/` is used even if another Composer
autoloader is loaded (e.g. a global Drush).

## Requirements

- Drupal 10.3 or 11.
- Outgoing HTTPS to `api.osv.dev`, `packages.drupal.org`, `packagist.org` and
  `updates.drupal.org`.
- Optional: [Ultimate Cron](https://www.drupal.org/project/ultimate_cron). A
  daily job is provided (`config/optional`).

## Configuration

*Configuration » System » Security Advisory Alert*
(`/admin/config/system/security-advisory-alert`), permission
**Administer security advisory alerts**:

- **Recipients**: one address per line, or comma-separated.
- **Report severities**: an email is sent when an advisory of one of these
  levels is found (default: critical and high). The email also lists the
  other advisories, for information. A PSA always triggers the email.
- **Sender address**: optional, the site address is used otherwise.

The page shows the last check of the codebase (date, site that ran it, result)
and has a **Run audit now** button.

Settings are in `security_advisory_alert.settings`: export them like any
config.

## Schedule

- With Ultimate Cron: job `security_advisory_alert_cron`, daily at a fixed time
  (the same on every site of a multisite).
- Without: `hook_cron()` runs the check on the first cron at least 20 h after
  the previous check (of any site, in a multisite).
- With no recipient configured, cron does nothing (no HTTP call, no log). To
  switch the alerts off on an environment, empty the recipients there, e.g.
  with a config split patch or a `settings.php` override
  (`$config['security_advisory_alert.settings']['recipients'] = '';`).
  "Run audit now" still runs the check and shows the result.

The fetched data is cached 12 h: in a multisite the other sites reuse it
within the same daily run, and the email is sent again only after a deploy
changes the installed packages.

## File storage

The lock, cache and last result are stored on disk rather than in the
database, so that the sites of a multisite (separate databases, shared
filesystem) share them; a single site uses them the same way.

Location, first match:

1. `<drupal root>/sites/.security_advisory_alert/`: used if it exists or if
   `sites/` is writable. Preferred when several front servers share `sites/`
   (each has its own `/tmp`). A deny-all `.htaccess` is written in it since
   `sites/` is in the webroot.
2. `<tmp>/security_advisory_alert_<project key>/`: fallback when `sites/` is
   not writable (e.g. local dev). Key = project path, Ansistrano
   `releases/<id>` stripped, so several projects on a server stay separate
   and the key survives deploys.

In both cases:

- Mode `2770` (files `0660`): the PHP-FPM user and the cron user must **share a
  group** (e.g. `www-data`) for the "Run audit now" button and cron to share
  the state.
- The directory is refused (logged error) if it is a symlink or belongs to
  another user and group.
- PHP-FPM and cron must resolve to the same location: if only one of them can
  write `sites/`, they keep separate states (the email may be sent twice a
  day).

With systemd `PrivateTmp=true` on PHP-FPM, FPM and CLI see different `/tmp`
directories: same consequence when the `/tmp` fallback is used.

## Email

HTML, rendered with the `security_advisory_alert_email` theme hook
(`templates/security-advisory-alert-email.html.twig`), which a theme can
override. Links from external feeds are only kept if they are http(s).

The module registers a mail plugin that keeps the HTML with core's mail
system; with Symfony Mailer it works as is.

## Testing with Drush

There is no dedicated Drush command: run the audit through the service.
In a multisite, add `--uri=<site>` to every command.

Run the audit now (same as the "Run audit now" button) and print the result:

```
drush php:eval 'print_r(\Drupal::service("security_advisory_alert.checker")->runAudit());'
```

`status` is one of `sent`, `already_sent`, `clean`, `not_sent` or `error`
(`error` holds the message).

Show the last result of the codebase, without running anything:

```
drush php:eval 'print_r(\Drupal::service("security_advisory_alert.checker")->getLastResult());'
```

Run it through cron instead:

```
# With Ultimate Cron.
drush cron:run security_advisory_alert_cron
# Without: hook_cron() skips if a check ran < 20 h ago, or if there is no
# recipient.
drush cron
```

Set a recipient for the test:

```
drush config:set security_advisory_alert.settings recipients 'me@example.com' -y
```

The data is cached 12 h per install: a second run in that window returns
`already_sent` without sending the email again. To force a fresh check and
email, delete the cache files (see [File storage](#file-storage)), keeping
the directory:

```
rm <storage dir>/*.json
```

Then check the logs:

```
drush watchdog:show --type=security_advisory_alert
```

## Logs

Channel `security_advisory_alert` (*Reports » Recent log messages*).

## Tests

```
vendor/bin/phpunit -c web/modules/contrib/security_advisory_alert
```
