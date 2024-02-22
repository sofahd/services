import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="services",
    version="0.2",
    description="Services for sofah",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/sofahd/services",
    packages=["services"])