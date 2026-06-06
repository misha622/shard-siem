from setuptools import setup, find_packages

setup(
    name="shard-enterprise",
    version="5.2.9",
    packages=find_packages(include=["core", "core.*", "modules", "modules.*"]),
    python_requires=">=3.11",
)
