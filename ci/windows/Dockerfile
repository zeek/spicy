# escape=`
# Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.
#
# Docker image for Windows CI builds of Spicy.

FROM mcr.microsoft.com/dotnet/framework/sdk:4.8-windowsservercore-ltsc2019

SHELL [ "powershell" ]

# Version field to invalidate Cirrus's build cache when needed.
ENV DOCKERFILE_VERSION=20260311

RUN Set-ExecutionPolicy Unrestricted -Force

# Install Chocolatey
RUN [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; `
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Install Visual Studio 2022 Build Tools and C++ workload.
RUN choco install -y --no-progress visualstudio2022buildtools --version=117.14.29
RUN choco install -y --no-progress visualstudio2022-workload-vctools --version=1.0.0

# Install build tools.
RUN choco install -y --no-progress winflexbison3
RUN choco install -y --no-progress msysgit
RUN choco install -y --no-progress python
RUN choco install -y --no-progress ccache

# Set working environment.
SHELL [ "cmd", "/c" ]
RUN setx /M PATH "%PATH%;C:\\Program Files\\Git\\bin;C:\\btest-venv\\Scripts"
RUN mkdir C:\build
WORKDIR C:\build

# Entry point starts the developer command prompt and launches PowerShell.
ENTRYPOINT ["C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\Common7\\Tools\\VsDevCmd.bat", "-arch=x64", "&&", "powershell.exe", "-NoLogo", "-ExecutionPolicy", "Unrestricted"]
