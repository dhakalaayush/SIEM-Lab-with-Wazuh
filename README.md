# Endpoint Monitoring And Threat Detection With Wazuh

This project explores **Security Operations and Monitoring** concepts, focusing on building a small-scale SOC using Wazuh. It covers:
- Log collection, management, and analysis
- SIEM architecture and features
- Endpoint monitoring (FIM, configuration assessment, vulnerability detection)
- Threat hunting, active response (firewall drop), malware detection
- Alerting (email) and incident response lifecycle (NIST-based)

![Dashboard](Pictures/Dashboard.png)

Tools
- Wazuh
- Agents: Ubuntu (manager and agent), Kali Linux (attacker and agent), Windows (agent with sysmon)
- Virtualbox
- Integration tools: Sysmon, VirusTotal, YARA
- Hydra (brute-force attacking tool)

Highlights
- Lab setup: Installed Wazuh agents in all VMs
- Sysmon setup: Sysmon was setup on Windows for logging
- File Integrity Monitoring (FIM): Real-time file/registry change detection
- Configuration Assessment: System configuration evaluation
![Alt text](images/Configuration_Assessment.png)
- Vulnerability Detection: CVE scanning + NIST lookup
![Alt text](images/Vulnerability_Detection.png)
- Threat Hunting: Dashboard queries, brute-force simulation
![Alt text](images/Threat_Hunting.png)
- Active Response: Firewall drop on repeated failures
- Malware Detection: VirusTotal scan
![Alt text](images/Malware_Detection.png)
- Alert: Email on high-severity events
![Alt text](images/Email_Alert.png)

Full Documentation
- Complete Report: (https://github.com/dhakalaayush/SIEM-Lab-with-Wazuh/blob/main/Security%20Operations%20and%20Monitoring.pdf)
- Includes lab setup steps, configurations and tests

References
- Wazuh Documentation: https://documentation.wazuh.com
- NIST CVE/NVD: https://nvd.nist.gov
- Incident Response Guide (NIST SP 800-61): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf
