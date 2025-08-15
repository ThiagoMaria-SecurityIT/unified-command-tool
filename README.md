# Unified Command & VirtualEnv Tool

[![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/yourusername/unified-command-tool)
[![Status](https://img.shields.io/badge/status-stable-brightgreen.svg)](https://github.com/yourusername/unified-command-tool)  

A comprehensive, unified desktop application that combines system command reference, cybersecurity monitoring, and Python virtual environment management in a single, intuitive interface.  

<img width="1599" height="850" alt="image" src="https://github.com/user-attachments/assets/ec388b26-b7d3-404b-882e-dd95bb349066" />    

## Table of Contents
- [Features](#features)
- [Screenshots](#screenshots)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [AI Transparency](#ai-transparency) 
- [License](#license)

## Features

### 🖥️ Unified Command Reference
- **Windows Commands**: Comprehensive collection of PowerShell commands for file operations, network management, and system administration
- **Linux/WSL Commands**: Extensive library of Linux commands with categorized tabs for easy navigation
- **Copy to Clipboard**: One-click copying of any command to your clipboard
- **Command Search**: Quickly find commands with the integrated search functionality

### 🛡️ Cybersecurity Dashboard
- **Network Activity Monitor**: Real-time monitoring of established network connections
- **Quick Security Actions**: One-click access to port scans, process audits, and firewall checks
- **Threat Level Indicator**: Visual indicator of system security status with periodic evaluation
- **Security Scans**: Integrated security scanning capabilities with Windows Defender

### 🐍 Virtual Environment Management
- **Path Configuration**: Easy setup of virtual environment, script, and Python executable paths
- **Command Templates**: Pre-built commands for creating, activating, and managing virtual environments
- **Integrated Terminal**: Execute commands directly within the application
- **PyInstaller Integration**: One-click creation of executable files from Python scripts

### 🖥️ Linux Terminal Emulator
- **Full Terminal Functionality**: Execute Linux commands directly in the application
- **Quick Command Buttons**: One-click execution of common Linux commands
- **Output Highlighting**: Color-coded output for commands, normal text, and errors
- **Command History**: Track and review executed commands

## Screenshots

### Windows & CyberSec Tab
<img width="1599" height="850" alt="image" src="https://github.com/user-attachments/assets/ec388b26-b7d3-404b-882e-dd95bb349066" />  

### Linux/WSL Tab
<img width="1592" height="847" alt="image" src="https://github.com/user-attachments/assets/9aca9fdd-7b1f-4363-9594-fb723097597d" />  


### VirtualEnv Tab
<img width="1398" height="852" alt="image" src="https://github.com/user-attachments/assets/9365c0b7-1efd-47a2-b095-21280e55971a" />  


## Installation

### Prerequisites
- Python 3.6 or higher
- Windows (recommended), Linux, or macOS
- For Linux/WSL: `xclip` package (for clipboard functionality)

### Install Required Packages
```bash
pip install pyperclip ttkbootstrap
```

### On Linux/WSL Only
```bash
sudo apt install xclip
```

### Running the Application
1. Clone the repository:
   ```bash
   git clone https://github.com/ThiagoMaria-SecurityIT/unified-command-tool
   cd unified-command-tool
   ```
2. **Create a virtual environment** (I recommend using Python's built-in venv):
   ```bash
   python -m venv venv
   ```
   (or `python3 -m venv venv` if you have multiple Python versions)

3. **Activate the virtual environment**:
   - On Windows:
     ```bash
     venv\Scripts\activate
     ```
   - On macOS/Linux:
     ```bash
     source venv/bin/activate
     ```
   - If none of the above worked, try a mix of both (if you are using Git Bash in Windows for example)
     ```bash
     source venv/Scripts/activate
     ```

4. Run the application:
   ```bash
   python unified_command_tool.py
   ```

## Usage

### Getting Started
1. Launch the application to open the main interface
2. Navigate between tabs using the tab bar at the top
3. Use the search bar in the header to find specific commands

### Windows & CyberSec Tab
- **Left Panel**: Browse categorized Windows commands
- **Right Panel**: 
  - Monitor network activity in real-time
  - Use quick actions for security scans
  - View threat level status

### Linux/WSL Tab
- **Left Panel**: Browse categorized Linux commands
- **Right Panel**:
  - Use the integrated terminal to execute commands
  - Click quick command buttons for common tasks
  - View command output with color highlighting

### VirtualEnv Tab
1. Configure your paths at the top of the tab:
   - Virtual Environment Path
   - Script Path
   - Python Executable Path
2. Browse command categories in the notebook:
   - Basic Commands
   - Advanced Commands
   - PowerShell Specific
   - Troubleshooting
   - Make Exe
3. Use the integrated terminal to execute commands
4. Copy commands to clipboard or execute them directly

### Common Workflows

#### Creating a Python Virtual Environment
1. Navigate to the VirtualEnv tab
2. Set your paths (or use defaults)
3. Go to the "Basic Commands" sub-tab
4. Click "Copy" next to "Create Virtual Environment"
5. Paste into your terminal or click "Execute" in the integrated terminal

#### Monitoring Network Connections
1. Navigate to the Windows & CyberSec tab
2. In the Network Activity panel, click "Refresh"
3. View active connections in real-time
4. Use "Clear Terminal" to reset the display

#### Executing Linux Commands
1. Navigate to the Linux/WSL tab
2. Use the command reference on the left to find commands
3. Either copy the command or use the integrated terminal on the right
4. For common tasks, use the Quick Command buttons

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Setup
1. Clone the repository
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install development dependencies:
   ```bash
   pip install -r requirements-dev.txt
   ```
4. Install the package in editable mode:
   ```bash
   pip install -e .
   ```

## AI Transparency  
This application was developed with AI assistance to generate and refine Python code, specifically designed for Cybersecurity and InfoSec professionals of all skill levels.  

**Important Notes:**  
- Do not use this application without evaluating security implications for your environment.  
- Always consult your Security IT department before deployment.  

**AI Models Used:**  
- [Manus AI](https://manus.ai)  
- [DeepSeek](https://deepseek.com)    


## License

Distributed under the MIT License. See `LICENSE` for more information.

## Acknowledgments

- [ttkbootstrap](https://github.com/israel-dryer/ttkbootstrap) for the beautiful themed widgets
- [pyperclip](https://github.com/asweigart/pyperclip) for cross-platform clipboard functionality
- The Python community for the excellent libraries that made this project possible
---  

## About the Author   

**Thiago Maria - From Brazil to the World 🌎**  
*Senior Security Information Professional | Passionate Programmer | AI Developer*

With a professional background in security analysis and a deep passion for programming, I created this Github acc to share some knowledge about security information, cybersecurity, Python and AI development practices. Most of my work here focuses on implementing security-first at companies and developer tools while maintaining usability and productivity.

Let's Connect:

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://www.linkedin.com/in/thiago-cequeira-99202239/)  
[![Hugging Face](https://img.shields.io/badge/🤗Hugging_Face-AI_projects-yellow)](https://huggingface.co/ThiSecur)  
 
## Ways to Contribute:   
 Want to see more upgrades? Help me keep it updated!    
 [![Sponsor](https://img.shields.io/badge/Sponsor-%E2%9D%A4-red)](https://github.com/sponsors/ThiagoMaria-SecurityIT) 
