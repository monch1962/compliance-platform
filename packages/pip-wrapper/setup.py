from setuptools import setup, find_packages

setup(
    name="cicd-gate",
    version="0.3.1",
    packages=find_packages(),
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "cicd-gate=cicd_gate.__main__:main",
        ],
    },
    python_requires=">=3.8",
)
