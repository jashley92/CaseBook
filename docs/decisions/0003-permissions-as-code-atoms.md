# 0003. Permissions are code-defined; roles are bundles; need-to-know is one query filter

- **Status:** Accepted
- **Recorded:** 2026-10-02

## Context

Organizations want their own roles ("Tier 2 analyst", "Privacy officer") mapped to their own AD groups. But a
permission only means something because code checks for it. A permission an administrator invented would be
honored by no code.

## Decision

- The **`Permission` enum** is the set of security atoms. It changes only with code.
- **Roles** are bundles of permissions: five locked system roles plus any number of custom roles. They are
  stored in the database and mapped to AD groups in-app. `SysAdmin` holds every permission, including ones
  added later.
- **Actions** are checked at the service boundary. Every mutating `CaseService` method looks up its required
  permission in `CaseActionPermissions` and fails closed if it has no entry. A unit test fails the build when
  a mutating method is missing from the map.
- **Visibility** (need-to-know) is one query filter, `CaseQueryExtensions.ForUser`, applied to every case
  query. It keys on the `ViewAllCases` permission, not on a role name.

## Alternatives considered

- **Role-name checks in code** (`IsInRole("Manager")`): breaks as soon as an organization renames or adds roles.
- **Fully administrable permissions:** see the context above.

## Consequences

- A new capability is a code change: add a `Permission` member and a policy, add the service-map entries, and
  decide which system roles get it.
- UI checks (`AuthorizeView`, hidden buttons) are a convenience. The service check is the enforcement.
- A not-permitted case and a missing case return the same "not found", so a restricted case's existence doesn't
  leak.
