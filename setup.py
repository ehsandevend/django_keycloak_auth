from setuptools import setup, find_packages

setup(
    name='django_keyckoak_auth',
    version='0.1.8',
    packages=find_packages(include=["django_keycloak_auth", "django_keycloak_auth.*"]),
    include_package_data=True,
    install_requires=[
        'Django>=3.2',
        'djangorestframework>=3.16.0',
        'josepy>=2.1.0',
        'python-jose>=3.3.0',
        'requests>=2.32.5',

    ],
    description='My reusable django keycloak auth',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='Ehsan Ahmadi (Funder)',
    url='https://github.com/ehsandevend',
    classifiers=[
        'Framework :: Django',
        'Programming Language :: Python :: 3',
    ],
)