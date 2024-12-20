# Zeus_Analysis
# Proactive Project: Detecting and Analyzing the Zeus Banking Trojan

## Overview
This project focuses on the detection and analysis of the Zeus Banking Trojan using a combination of tools and techniques, including memory analysis, network monitoring, and intrusion detection. By simulating Zeus malware execution in a controlled environment, the project highlights proactive methods for malware detection and forensic investigation.

## Objectives
- Simulate the execution of Zeus malware in a virtualized environment.
- Monitor and capture network traffic and system logs during malware execution.
- Conduct memory analysis and process inspection to identify malicious activity.
- Develop and apply custom detection rules using tools like Suricata, Splunk, and Yara.
- Generate actionable insights for detecting and responding to Zeus-related attacks.

## Requirements
### Tools
- **Wireshark**: For capturing and analyzing network traffic.
- **FTK Imager**: For creating memory dumps.
- **Suricata**: For intrusion detection and log generation.
- **Splunk**: For centralized log analysis and dashboard creation.
- **Volatility**: For memory analysis and forensic investigations.
- **Yara**: For creating and applying custom malware detection rules.

### Environment
- Windows 7 Virtual Machine
- Kali Linux (for Suricata, Splunk, and analysis)

## Steps
### 1. Preparation
- Set up a Windows 7 VM.
- Obtain Zeus malware from theZoo repository and extract it using the password `infected`.

### 2. Simulate Malware Execution
- Execute the Zeus malware on the VM.
- Capture network traffic using Wireshark to generate a PCAP file.
- Examine system logs to identify anomalies such as process creation and registry modifications.

### 3. Memory Analysis
- Use FTK Imager to dump the VM’s memory.
- Analyze the memory dump using Volatility to identify:
  - Suspicious processes
  - Potential code injections
  - Network activity linked to high/random ports

### 4. Network Monitoring and Intrusion Detection
- Configure Suricata to monitor network traffic and generate alerts.
  - Write custom rules for Zeus-specific patterns.
  - Compare logs before and after adding Zeus-specific rules.
- Forward Suricata logs to Splunk for centralized analysis.

### 5. Splunk Integration
- Configure `inputs.conf` in Splunk to monitor Suricata logs (e.g., `eve.json`, `fast.log`, `stats.log`).
- Create dashboards to:
  - Visualize abnormal outbound traffic.
  - Correlate network anomalies with system activity.
  - Identify high-risk sources and prioritize investigations.

### 6. Yara Rule Application
- Develop Yara rules to detect Zeus artifacts in binaries and memory dumps.
- Apply rules to scan the infected system for Zeus-specific patterns.

## Results
### Memory Analysis
- Identified suspicious processes like `services.exe` and `svchost.exe` with unusual memory permissions.
- Detected C2 communication patterns and code injections.

### Network Monitoring
- Highlighted suspicious connections to external IPs and unusual port usage.
- Increased detection alerts after adding Zeus-specific rules in Suricata.

### Splunk Dashboards
- Visualized traffic patterns and anomalies.
- Correlated system events with Suricata alerts for detailed incident timelines.

### Yara Detection
- Successfully flagged Zeus-related binaries, configurations, and shellcode using custom rules.

## Future Work
- Automate the analysis workflow using scripts.
- Integrate machine learning models for anomaly detection.
- Expand the rule set for detecting advanced malware variants.

## Contact
For questions or collaboration, please reach out to [01210093372].

