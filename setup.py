from setuptools import setup, find_packages

with open("README.md", "r") as fs:
    long_description = fs.read()

setup(
    name="netzeus_core_security",
    version="0.0.2",
    description="NetZeus Core Security module for managing security context across all microservices/plugins",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Brandon Spendlove",
    author_email="brandon.spendlove@netzeus.io",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "bcrypt>=4.0.0",
        "passlib>=1.7.4",
        "PyJWT>=1.7.1",
        "fastapi>=0.88.0",
    ],
)
