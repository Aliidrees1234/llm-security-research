from setuptools import setup, find_packages

setup(
    name="shield-security",
    version="0.6.0",
    author="Ali Yasin Idrees",
    author_email="aa1466805@gmail.com",
    description="SHIELD — Automated security layer for LLM-assisted web development",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Aliidrees1234/llm-security-research",
    packages=find_packages(),
    install_requires=[
        "bandit>=1.9.4",
        "bcrypt>=4.0.0",
        "colorama>=0.4.6",
        "astor>=0.8.1",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "semgrep",
        ]
    },
    entry_points={
        "console_scripts": [
            "shield=shield.cli:main",
        ],
    },
    python_requires=">=3.10",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
    ],
    keywords=[
        "security", "sast", "bandit", "semgrep",
        "llm", "ai", "code-security", "vulnerability"
    ],
)