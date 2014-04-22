#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
	name="kdsp",
	version="0.1.1-dev",
	description="Protocol library for KDSP (Kismet Drone-Server Protocol)",
	author="Michael Farrell",
	author_email="micolous@gmail.com",
	url="https://github.com/micolous/kdsp",
	license="LGPL3+",
	requires=[
		'Twisted (>=12.0.0)',
		'pytz',
	],
	packages=find_packages('src'),
	package_dir={'': 'src'},
	
	
	entry_points={
		'console_scripts': [
		]
	},
	
	classifiers=[
	
	],
)

