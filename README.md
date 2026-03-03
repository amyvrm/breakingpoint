# Breaking Point Vulnerability Testing

A comprehensive vulnerability testing framework using Breaking Point for automated CVE detection and network traffic analysis. This project enables systematic vulnerability testing through PCAP replay, filter discovery, and tracking of CVE exploits.

## 🎯 Purpose

This repository serves as my **personal learning and development journey** for mastering:
- Vulnerability testing methodologies
- Network security analysis and threat detection
- Infrastructure automation and DevOps practices
- Python development and testing frameworks
- Cloud infrastructure management with AWS

## ✨ Features

- **Automated Vulnerability Testing**: Leverage Breaking Point for systematic CVE detection
- **PCAP Analysis**: Capture, replay, and analyze network traffic for exploit verification
- **CVE Tracking**: Comprehensive filter management and vulnerability tracking
- **Infrastructure as Code**: AWS automation using Terraform
- **CI/CD Pipeline**: Jenkins integration for continuous testing
- **Containerization**: Docker support for reproducible test environments
- **Notifications**: Teams integration for real-time test results

## 📁 Project Structure

```
├── src/                    # Core Python scripts and shell utilities
├── tests/                  # Test suites for validation
├── docker_files/           # Docker configurations
├── jenkins_files/          # Jenkins pipeline definitions
├── iac_src/                # Terraform infrastructure code
├── dep/                    # Dependencies and requirements
└── config/                 # Configuration files
```

## 🛠️ Tech Stack

- **Languages**: Python, Bash, Groovy
- **Infrastructure**: AWS, Terraform
- **CI/CD**: Jenkins
- **Containerization**: Docker
- **Testing**: Breaking Point, pytest
- **Tools**: pkt2flow, PCAP analysis tools

## 📚 Learning Goals

This project helps me develop expertise in:
- Security testing automation
- Network traffic analysis
- Cloud infrastructure management
- DevOps best practices
- Test-driven development

## 🚀 Getting Started

### Prerequisites
- Python 3.x
- Docker
- AWS CLI configured
- Breaking Point access

### Installation
```bash
# Clone the repository
git clone https://github.com/amyvrm/breakingpoint.git

# Install dependencies
pip install -r dep/requirements.txt

# Configure settings
cp config/.config.ini.example config/.config.ini
# Edit config/.config.ini with your settings
```

## 📝 License

This is a personal learning project. Feel free to explore and learn from it.

## 🔗 Connect

This project is part of my continuous learning journey in cybersecurity and DevOps. Feedback and suggestions are always welcome!