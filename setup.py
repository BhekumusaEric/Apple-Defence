from setuptools import setup, find_packages

setup(
    name="apple-defence",
    version="0.1.0",
    description="A red agent and blue agent twin security project for iOS defence",
    author="Bhekumusa Eric Ntshwenya",
    author_email="bhntshwcjc025@student.wethinkcode.co.za",
    packages=find_packages(),
    install_requires=[
        "numpy>=1.20.0",
        "pandas>=1.3.0",
        "scikit-learn>=1.0.0",
        "tensorflow>=2.8.0",
        "torch>=1.10.0",
        "transformers>=4.18.0",
        "frida>=15.0.0",
        "objection>=1.11.0",
        "pwntools>=4.7.0",
        "pyobjc>=8.0",
        "requests>=2.27.0",
        "pyyaml>=6.0",
        "tqdm>=4.62.0",
    ],
    python_requires=">=3.8",
)
