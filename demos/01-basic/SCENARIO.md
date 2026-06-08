# Demo 01 - Basic: SOC 2 + HIPAA startup

A seed-stage health-tech startup, **Acme Health**, needs to get audit-ready
for a SOC 2 Type II report and also handles protected health information
(PHI), so it must align with the HIPAA Security Rule.

They have 18 employees, run on AWS, and store customer data plus PHI.

## Run it

Generate the full policy set as JSON:

```bash
python -m policyforge --format json generate demos/01-basic/questionnaire.json
```

See the control-coverage map (which audit controls each policy satisfies and
where the gaps are):

```bash
python -m policyforge coverage demos/01-basic/questionnaire.json
```

List every supported framework and control:

```bash
python -m policyforge frameworks
```

## What to expect

Because the company handles PHI and PII, POLICYFORGE emits the encryption and
data-retention policies in addition to the always-on core policies
(information security, access control, incident response, training). The
coverage report shows SOC 2 and HIPAA controls mapped to the generated
policies, with any unmapped controls flagged as gaps.
