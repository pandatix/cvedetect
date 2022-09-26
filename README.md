# CVE-Detect

[![Coverage Status](https://coveralls.io/repos/github/pandatix/cvedetect/badge.svg?branch=master)](https://coveralls.io/github/pandatix/cvedetect?branch=master)

CVE-Detect gives a sample app that detect CVEs on components trees.

It's based on researches on CPE v2.3 future Release 5, NVD analysis, CVE detections and automated inventory AI.

## TODO

 - [ ] Implement complete `match` algorithm
 - [ ] Implement `MDCN` algorithm
 - [ ] Harden inputs through scalars
 - [ ] Add score filtering (filter on base, environmental and temporal scores + attributes values)
 - [ ] Improve support of CPE v2.3 Release 4 with `github.com/pandatix/go-cpe` when released
 - [ ] Provide good tests with >85% code coverage
 - [ ] Provide API validation tests

## Disclaimer

Take a look at the license before using this project.

Moreover, there are many TODOs that disable this sample app to be used professionnaly/safely :
 - the database is memory-only, so the system does not provide integrity/saves on the data through time (in case the binary reboots).
 - the scalability of such a system is impossible because of the memory-only database.
 - there is a lack of interesting data supported by the data model, like references and their tags for a SIEM.
 - API transactions are not ACID, which could lead to inconsistencies in HA deployments.
 - `MDC1` is currently used for detections, covering ~80% of the whole NVD. `MDCN` should be implemented in order to give better results based on the context.
 - the `match` algorithm used by MDCs depends on an external dependency that is not perfectly suited for CPEs versions, and does not depend on any SCAP-approved version criteria (condition in which a version interval should be replaced by an enumeration). Additionaly, it is a simpler implementation of`match` as it does not cover wildcards in versions.
 - The NIST-IR 7695, CPE dictionnary and NVD contains known vulnerabilities/issues that are still not fixed, so can't be handled by this implementation.
 - it does not provide a way to create an inventory that will be consumed by the tool.
 - it does not provide a way to raise alerts in case of new detections, update, or deletes.
 - according to [Varonis](https://www.varonis.com/blog/what-is-siem), it does not gives enough metrics and tracability to become a SIEM ("When was it detected ?", "Since when the CVE exist ?" are questions that can't be answered ; MatchCircuit is not handled to explain why it matched).
 - it does not strongly validates inputs, especially of the NVD (that must be considered as out of trust).
 - there is not access control, so it can't be used out of a single team with no privilege management, which is not a good idea/security practice.
 - the API has not been tested (but needs to, with RobotFramework maybe).

To sum up : **do not use in production environment, or as a safe tool for security monitoring**.

## Examples

### Getting all CVEs related to a VP

```graphql
query QueryCVEs($input: QueryCVEInput!) {
    queryCVEs(input: $input) {
        id
        description
        configurations {
            negate
            operator
            cpeMatches {
                vulnerable
                cpe23
            }
        }
        cvss31 {
            vector
            baseScore
        }
    }
}
```

```json
{
    "input": {
        "vp": "gitea:gitea"
    }
}
```

The previous has the equivalent curl command.

```bash
curl -X POST http://localhost:8080/graphql \
    -d '{"query":"query QueryCVEs($input:QueryCVEInput){queryCVEs(input:$input){id description configurations{negate operator cpeMatches{vulnerable cpe23}}cvss31{vector baseScore}}}","variables":{"input":{"vp":"gitea:gitea"}}}'
```

### Adding a Component

```graphql
mutation AddComponent($input: AddComponentInput!) {
    addComponent(input: $input) {
        id
        name
        cpe23
        cves {
            id
            description
            configurations {
                negate
                operator
                cpeMatches {
                    vulnerable
                    cpe23
                    versionStartIncluding
                    versionStartExcluding
                    versionEndIncluding
                    versionEndExcluding
                }
            }
            cvss31 {
                vector
                baseScore
            }
        }
    }
}
```

```json
{
    "name": "Gitea",
    "cpe23": "cpe:2.3:a:gitea:gitea:1.12.6:*:*:*:*:docker:amd64:*"
}
```

The previous has the equivalent curl command.

```bash
curl -X POST http://localhost:8080/graphql \
    -d '{"query":"mutation AddComponent($input:AddComponentInput!){addComponent(input:$input){id name cpe23 cves{id description configurations{negate operator cpeMatches{vulnerable cpe23 versionStartIncluding versionStartExcluding versionEndIncluding versionEndExcluding}}cvss31{vector baseScore}}}}","variables":{"input":{"name":"Gitea","cpe23":"cpe:2.3:a:gitea:gitea:1.12.6:*:*:*:*:docker:amd64:*"}}}'
```
