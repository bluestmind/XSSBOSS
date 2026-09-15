# Security policy

XSSBOSS Collector is intended only for assets you own or are explicitly authorized to assess.

Do not use it to evade access controls, collect personal data without a lawful basis, or access systems outside a written scope. The `authorized_use` setting records operator intent but does not grant authorization.

For sensitive targets:

- use an exact scheme/host/path scope and explicit deny rules;
- keep private-network access disabled unless the target is an approved internal environment;
- leave query/body retention disabled;
- disable response-body evidence if pages may contain regulated or customer data;
- protect the SQLite database and evidence directory with operating-system access controls;
- review exported files before sharing them.

Report suspected collector vulnerabilities privately to the project owner. Include the affected version, reproduction steps, impact, and a safe test case. Do not test a report against third-party systems.

