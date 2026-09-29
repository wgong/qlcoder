```User
❯ let us do it - prototype option A, the direct agentic triage mode, we can reuse some CVE metadata feature, and use metadata info to build the prompt to detect vulnerability, can you create 3 new scripts in /home/gongai/projects/AI-Tools/qlcoder/scripts, with the 3 atomic functional units, (a) cve_detect.py - given cve-id, it will fetch its metadata info against national cve registry, with potential fix info, generate a analysis report (in .yaml format), (b) cve_patch.py - use the .yaml report from (a) to generate fixes be it repo upgrade or actual code changes, generate a report of fixes per original CVE finding, (c) cve_verify.py - generate test-suite based on report from (b) and run the tests, generate a report to show either fix is effective or not, what do you think? please document my requirement here, suggest improvements

❯ can you rename detect_report.yaml to cve_findings.yaml, list each finding with code file path and affected line(s) (2) rename patch_report.yaml to cve_patch.yaml, list fixes one-by-one, with fix-name, fix-description, actual fixed code-snippets (use yaml multi-line syntax "|"), so one can review the complete changes in one .yaml report (3) rename verify_report.yaml to cve_verified.yaml with regression and verification test-suite listed one-by-one, with PASS or FAILED results, what do you think, basically these 3 .yaml files together represent a complete and auditable trace of our work, which is very important in address vulnerability

❯ can you create /home/gongai/projects/AI-Tools/qlcoder/scripts/cve_secure.py as the main script to orchestrate above 3 scripts, please use click CLI, with each unit run separately or together as a full pipe-line, add this to readme-approach.md too

```


