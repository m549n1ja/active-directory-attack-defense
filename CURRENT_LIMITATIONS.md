# Current Limitations — active-directory-attack-defense

This document is an honest accounting of what this lab does and does not do, and what would be different in a production environment.

---

## What This Lab Is

A controlled, single-site Active Directory environment built specifically to practice and document the canonical AD credential attack chain — from initial reconnaissance through credential dumping — and to demonstrate detection engineering and hardening skills in response to those attacks.

The lab produces real telemetry from real tools against a real domain. Every event count, every alert, and every screenshot represents actual activity from the lab environment.

---

## What This Lab Is Not

This is not a hardened production deployment. It is not a simulation of a mature enterprise environment. Several configurations that would be unacceptable in production were intentional for the purpose of practicing specific attacks.

---

## Known Limitations

### 1. Single domain, no forest trust
The lab uses a single soc.local domain with no child domains, no forest trusts, and no cross-domain attack paths. Techniques like cross-forest Kerberoasting, SID history abuse, or trust-based lateral movement are not covered.

### 2. Intentional misconfigurations were created and then remediated
svc-sql-report had RC4 enabled and svc-backup-ops had PreAuth disabled — by design. These were exploited in the attack chain and then hardened in Phase 10. A real environment would ideally never have these configurations in the first place.

### 3. No Microsoft Defender for Identity (MDI)
MDI provides native DC-level sensor coverage and would have detected SharpHound LDAP burst, Kerberoasting, and DCSync without requiring custom KQL rules or a manually configured Winlogbeat pipeline. This lab demonstrates the detection engineering skills required in environments that rely on a generic SIEM rather than a purpose-built identity threat detection product.

### 4. No LAPS (Local Administrator Password Solution)
Local admin credentials are not managed by LAPS. In a production environment, LAPS would randomize local admin passwords per machine, preventing lateral movement via pass-the-hash using local credentials.

### 5. No tiered administration model
r.hayes uses the same Domain Admin account to log into workstations, servers, and the domain controller. A production environment would use a Tier 0 / Tier 1 / Tier 2 separation to limit where privileged credentials are cached.

### 6. Winlogbeat was not installed on WIN-DC01 until Phase 5
This was discovered during the attack chain as a detection gap — Event 4769 was not reaching the SIEM. It is documented as a real finding and has been corrected. In a production environment, the telemetry pipeline would be validated before any testing began.

### 7. ELK uses ssl_verification_mode none for Logstash → Elasticsearch
Certificate verification was relaxed in the Lab 1 ELK configuration. A production deployment would validate the full certificate chain between Logstash and Elasticsearch.

### 8. Elastic uses a broad elastic superuser for Beats agents
The Beats agents authenticate to Elasticsearch with the elastic superuser (credentials stored in environment variables). A production deployment would use API keys scoped to the minimum required privileges.

### 9. Golden Ticket and Pass-the-Ticket not executed
Mimikatz was not successfully used to forge a Golden Ticket (KRBTGT hash was not successfully extracted given PPL blocking). This technique is documented as a planned improvement in the incident report.

### 10. No SOAR integration or automated response
Alerts in Kibana require manual analyst review. A production environment would integrate with a SOAR platform to automate triage, enrichment, and containment actions.

---

## Planned Improvements

| Improvement | Priority | Notes |
|---|---|---|
| BloodHound before/after comparison screenshots | High | Pending Phase 10 completion |
| MITRE ATT&CK Navigator export | High | Pending |
| Incident report (full DFIR format) | High | Pending |
| Golden Ticket technique and detection | Medium | Requires KRBTGT hash — blocked by PPL in this run |
| LAPS deployment | Medium | Would eliminate local admin lateral movement path |
| Tiered administration model | Medium | Separation of admin accounts by tier |
| MDI evaluation | Low | Out of scope for this lab; documented as production alternative |
