# Scope and Limitations — Active Directory Attack & Defense Lab

---

## Project Scope

This project documents the construction and adversarial evaluation of a single-site Active Directory environment, with scope bounded to the canonical credential attack chain and its corresponding detection and hardening measures. The environment was built and operated under controlled conditions, and several configurations present — including weak foothold credentials, RC4-enabled service accounts, and disabled Kerberos pre-authentication — were introduced deliberately to enable specific attack techniques. Those conditions do not reflect the intended end state of the domain; they reflect the starting conditions under which the attack chain was executed and subsequently remediated.

Every event count, alert, and screenshot in this repository reflects activity generated in the actual lab environment. No data has been fabricated or approximated.

---

## Known Limitations

**Single domain, no inter-forest trust.** The environment consists of a single soc.local domain with no child domains, no forest trusts, and no cross-forest replication relationships. Attack techniques that rely on trust relationships — including cross-forest Kerberoasting, SID history injection, and trust-based lateral movement — are outside the scope of this project.

**Misconfigurations were introduced, not inherited.** The vulnerable service account configurations exploited in Phases 5 and 6 were created deliberately. In a production environment, these conditions typically arise through accumulated configuration drift rather than deliberate provisioning. The project documents the exploitation and remediation of these configurations but does not simulate the detection of their initial introduction.

**No Microsoft Defender for Identity.** MDI deploys a sensor directly on the domain controller and provides native detection coverage for SharpHound enumeration, Kerberoasting, AS-REP Roasting, and DCSync without requiring a separately configured SIEM pipeline. The detection approach used in this project — Winlogbeat forwarding to Elastic Security with custom KQL rules — represents the engineering required in environments that rely on a general-purpose SIEM rather than a purpose-built identity threat detection product. MDI is documented as a production alternative in the hardening discussion.

**No Local Administrator Password Solution (LAPS).** Local administrator credentials on WIN10-ADCLIENT are not managed or rotated by LAPS. In a production domain, LAPS randomizes local administrator passwords per machine, eliminating the lateral movement path available when a single local admin credential is shared across multiple endpoints.

**No tiered administration model.** The r.hayes account is used as both the privileged administrative credential and the account exercised in attack scenarios. A production environment would enforce separation between Tier 0 accounts (domain controller access), Tier 1 accounts (server access), and Tier 2 accounts (workstation access) to limit the scope of credential exposure at any single tier.

**Winlogbeat was absent from WIN-DC01 at the start of Phase 5.** Event 4769 and Event 4768 were not reaching the SIEM during the initial Kerberoasting and AS-REP Roasting executions because Winlogbeat had not been deployed to the domain controller. The gap was identified through the absence of expected telemetry, corrected by deploying Winlogbeat on WIN-DC01, and documented as a finding. In a production environment, telemetry pipeline completeness would be validated as a prerequisite to detection rule deployment.

**TLS certificate validation is relaxed in the shared ELK configuration.** The Logstash-to-Elasticsearch pipeline uses `ssl_verification_mode: none`, a setting carried over from the Lab 1 ELK deployment where it was introduced to reduce initial configuration friction. A production deployment would enforce full certificate chain validation between pipeline components.

**Beat agents authenticate as the elastic superuser.** Winlogbeat credentials are stored as environment variables referencing the elastic superuser account. A production deployment would provision dedicated service accounts or API keys with the minimum privileges required for index write operations.

**Golden Ticket technique was not executed.** Mimikatz was not used to forge a Kerberos Golden Ticket in this project, as the KRBTGT hash was not successfully extracted — the LSASS dump was blocked by Defender PPL and secretsdump was not targeted at the KRBTGT account explicitly. The Golden Ticket technique (T1558.001) is documented as a planned extension in the incident report.

**Alert response is fully manual.** Kibana Security surfaces alerts for analyst review without automated triage, enrichment, or containment. A production SOC would integrate a SOAR platform to automate initial response steps.

---

## Planned Improvements

The following items represent documented gaps between the current project state and a more complete body of work. They are recorded here rather than corrected silently so that the state of the project at any given commit reflects what was actually accomplished rather than what was intended.

| Item | Status |
|---|---|
| BloodHound before/after attack path comparison | Pending Phase 10 completion |
| MITRE ATT&CK Navigator layer export | Pending |
| Incident report in full DFIR format | Pending |
| Golden Ticket execution and detection | Planned — requires KRBTGT hash extraction |
| LAPS deployment and validation | Planned |
| Tiered administration model | Planned |
| MDI as an alternative detection architecture | Out of scope — documented as a production consideration |
