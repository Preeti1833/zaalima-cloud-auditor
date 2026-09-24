from pathlib import Path

from setuptools import find_packages, setup

this_dir = Path(__file__).parent
long_description = (this_dir / "README.md").read_text(encoding="utf-8")

setup(
    name="cloud-auditor",
    version="0.1.0",
    description="Cloud Infrastructure Auditor & Cost Optimizer — a CLI for DevOps/FinOps teams.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Zaalima Development",
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.9",
    install_requires=[
        "typer[all]>=0.9.0",
        "rich>=13.7.0",
        "boto3>=1.34.0",
        "botocore>=1.34.0",
        "google-cloud-compute>=1.19.0",
        "google-cloud-monitoring>=2.21.0",
        "google-auth>=2.29.0",
        "PyYAML>=6.0.1",
    ],
    entry_points={
        "console_scripts": [
            "cloud-auditor=cloud_auditor.cli:app",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Intended Audience :: System Administrators",
        "Topic :: Utilities",
    ],
)
