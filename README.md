# Security Workflow Project

This project is to test out different security workflow we can find around the web. Caliberating them and testing them out in a github environnement.

list of solutions to explore:
- [x] gitleaks ([website](https://github.com/zricethezav/gitleaks))
- [ ] spectralops ([website](https://spectralops.io/))
- [ ] awslabs/git-secrets ([website](https://spectralops.io/))
- [ ] whispers ([website](https://github.com/Skyscanner/whispers))
- [ ] <s>gittyleaks ([website](https://github.com/kootenpv/gittyleaks))</s> (to simple)
- [ ] git-all-secrets ([website](https://github.com/anshumanbh/git-all-secrets)) (uses the combination of two other tools)
- [ ] Sonar Qube ([website](https://www.sonarqube.org/))
- [x] GitGuardian ([website](https://www.gitguardian.com/))
- [ ] gitMiner ([website](https://linuxsecurity.expert/tools/gitminer/))
- [ ] Gitrob ([website](https://linuxsecurity.expert/tools/gitrob/))
- [ ] AIL framework ([website](https://linuxsecurity.expert/tools/ail-framework/))
- [ ] ACRA ([website](https://linuxsecurity.expert/tools/acra/))
- [ ] <s>DNSteal ([website](https://linuxsecurity.expert/tools/dnsteal/))</s> (Other tool, usefull for OWASP sec project)
- [ ] SMBMap ([website](https://linuxsecurity.expert/tools/smbmap/))


## Git Guardian

Detect secrets exposed in internal repositories. It is used on GitHub, to detect secrets leaked on public GitHub and warning the concerned parties.

It also has a dashboard so you can pull out all the information you need.

GitGuardian has created the finest library of automated secrets detectors thanks to a dedicated R&D team. You have the possibility of choosing which secrets detectors you want to operate on your perimeter.

### Pricing

#### Open source and Small teams

It is free, but only available for public repositories listed under a GitHub Organization.

It is free for Teams of 1 to 25 developers. But the number of calls to analyse your code is limited. 1k API (scan anything you want) calls per month.

Available in Saas only

#### Standard

200$ per year per developer. (from website)

Available in Saas and on Prem

#### Entreprise

For entreprise with over 200 developper, they are open to talk and schedule a demo.

Available in Saas and on Prem

### Secrets

Most corporate leaks on GitHub occur on developers’ personal public repositories, as opposed to official company’s open source repositories. In the vast majority of the cases, these leaks are unintentional, not malevolent. With 40M+ developers using GitHub, any company with a lot of developers is exposed to the platform.

Developers now build software in a decentralized, cloud and SaaS-friendly way. As a result, they increasingly use API keys, database credentials, private keys, certificates, ... This leads to secrets spreading within the organizations and the public domain.

## gitLeaks ([wiki](https://github.com/zricethezav/gitleaks))

Gitleaks is a SAST tool for detecting hardcoded secrets like passwords, api keys, and tokens in git repos. Gitleaks is an easy-to-use, all-in-one solution for finding secrets, past or present, in your code.

### Pricing

It's an open source project on GitHub, it can be used for free, but a small donation can be made to the author [zricethezav](https://github.com/zricethezav)

### Uses

GitLeaks can be activated on your local machine and make reports. Or used as a pre-commit hook to stop code from being pushed, if they contain hardcoded secrets. It can also be used simply in workflow.

```
Usage:
  gitleaks [OPTIONS]

Application Options:
  -v, --verbose             Show verbose output from scan
  -q, --quiet               Sets log level to error and only output leaks, one json object per line
  -r, --repo-url=           Repository URL
  -p, --path=               Path to directory (repo if contains .git) or file
  -c, --config-path=        Path to config
      --repo-config-path=   Path to gitleaks config relative to repo root
      --clone-path=         Path to clone repo to disk
      --version             Version number
      --username=           Username for git repo
      --password=           Password for git repo
      --access-token=       Access token for git repo
      --threads=            Maximum number of threads gitleaks spawns
      --ssh-key=            Path to ssh key used for auth
      --unstaged            Run gitleaks on unstaged code
      --branch=             Branch to scan
      --redact              Redact secrets from log messages and leaks
      --debug               Log debug messages
      --no-git              Treat git repos as plain directories and scan those files
      --leaks-exit-code=    Exit code when leaks have been encountered (default: 1)
      --append-repo-config  Append the provided or default config with the repo config.
      --additional-config=  Path to an additional gitleaks config to append with an existing config. Can be used with --append-repo-config to append up to three configurations
  -o, --report=             Report output path
  -f, --format=             JSON, CSV, SARIF (default: json)
      --files-at-commit=    Sha of commit to scan all files at commit
      --commit=             Sha of commit to scan or "latest" to scan the last commit of the repository
      --commits=            Comma separated list of a commits to scan
      --commits-file=       Path to file of line separated list of commits to scan
      --commit-from=        Commit to start scan from
      --commit-to=          Commit to stop scan
      --commit-since=       Scan commits more recent than a specific date. Ex: '2006-01-02' or '2006-01-02T15:04:05-0700' format.
      --commit-until=       Scan commits older than a specific date. Ex: '2006-01-02' or '2006-01-02T15:04:05-0700' format.
      --depth=              Number of commits to scan

Help Options:
  -h, --help                Show this help message
```
