from setuptools import setup

setup(
    name="int-dynamic-engine",
    version="3.0.2",
    packages=["inte"],
    package_data={"inte": ["_native/*.cpp", "_native/*.h"]},
    include_package_data=True,
    install_requires=[],
    license="MIT",
    description="High-performance C++17 AES-256-GCM Encrypted Out-of-Core Storage & Memory Engine",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Nikila Udana",
    author_email="intxteam@gmail.com",
    url="https://github.com/nikilaudana/int-dynamic-engine",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: C++",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Topic :: Database :: Database Engines/Servers",
        "Topic :: Security :: Cryptography",
    ],
    python_requires=">=3.8",
)
