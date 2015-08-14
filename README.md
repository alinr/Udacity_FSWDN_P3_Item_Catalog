# Item Catalog Application

This application will display, create, edit & delete items and their categories.
You also have the possibility to access items & categories through a JSON- and/or XML-API.

## Table of contents

- [Project Specification](#project-specification)
- [How to run](#how-to-run)
- [Remarks](#remarks)
- [Requirements](#requirements)
- [Shoutouts & References](#shoutouts-references)

## Project Specification

An application that provides a list of items within a variety of categories as well as a user registration and
authentication system. Registered users will have the ability to post, edit and delete their own items.

## How to run

### Install Virtualbox
https://www.virtualbox.org/wiki/Downloads


### Install Vagrant
https://www.vagrantup.com/downloads

Verify that Vagrant is installed and working by typing in the terminal:

	vagrant -v   # will print out the Vagrant version number

### Clone the Repository
Once you are sure that VirtualBox and Vagrant are installed correctly execute the following:

	git clone https://github.com/alinr/Udacity_FSWDN_P3_Item_Catalog.git
	cd Udacity_FSWDN_P3_Item_Catalog
	cd vagrant

### Verify that these files exist in the newly cloned repository:

	--catalog             #folder containing tournament files
	----project.py        #file that contains the python functions which unit tests will run on
	----database_setup.py    		# SQLite Database Schema preparation
	----dummydata.py         		# Dummy Data
	----fb_client_secrets.json		# JSON file with Facebook Credentials
	----google_client_secrets.json	# JSON file with Google Plus Credentials
	----templates					# folder containing HTML templates
	------base						# folder containing layout HTML templates
	--------layout.html				# standard layout template
	------forms						# folder containing HTML templates with forms
	--------deleteItem.html			# HTML Template for deleting an item
	--------editItem.html			# HTML Template for editing an item
	--------newCategory.html		# HTML Template for creating a new category
	--------newItem.html			# HTML Template for creating a new item
	------home.html					# HTML Template: Homepage of the Item Catalog Website
	------login.html				# HTML Template: Login page
	------showCategory.html			# HTML Template: Show items of one category
	------showItem.html				# HTML Template: Show one item
	--Vagrantfile            		# template that launches the Vagrant environment
	--pg_config.sh           		# shell script called by Vagrantfile that performs configurations

### Launch the Vagrant Box

	vagrant up   #to launch and provision the vagrant environment
	vagrant ssh  #to login to your vagrant environment

### Enter the Catalog

	cd /
	cd vagrant
	cd catalog

### Initialize the database

	python database_setup.py

### Populate the database with dummy data

	python dummydata.py

### Google Client ID & Secret

As the app uses Google for authentication, the next step you have to obtain a client id and client secret from Google:
1. Go to the [Google Developer Console](https://console.developers.google.com/project).
2. Create a new project.
3. Go to **APIs & auth - Consent screen** and select a valid Email address.
4. Go to **APIs & auth - Credentials** and download the JSON file
5. Copy the content of the JSON file to google_client_secrets.json

### Facebook Client ID & Secret

As the app uses also Facebook for authentication, the next step you have to obtain a client id and client secret from Facebook:
1. Go to the [Facebook Developer](https://developers.facebook.com/apps/).
2. Create a new app (www - website).
3. Get the App ID & App Secret
4. Copy the App ID & Secret to the fb_client_secrets.json

### Run the Application

	python project.py

You are now able to login via Google+ or Facebook to the application.
After successfully login you can view, create, edit, delete items & categories.

### Shutdown Vagrant machine

	vagrant halt

### Destroy the Vagrant machine

	vagrant destroy


## Remarks

- The app uses [Jasny Bootstrap's](http://jasny.github.io/bootstrap/javascript/#fileinput) file input widget for the picture upload.
- The pictures are stored in the database.
- The app uses nonces to prevent cross-site request forgeries (CSFR) when creating, updating and deleting items.
- The app offers two API endpoints:
	- **JSON:**
		- /categories/JSON
		- /category/<int:category_id>/JSON
		- /category/<int:category_id>/item/<int:item_id>/JSON
	- **XML:**
		- /categories/XML
		- /category/<int:category_id>/XML
		- /category/<int:category_id>/item/<int:item_id>/XML


## Requirements
- Python 2.7.9
- Flask 0.9
- Werkzeug 0.8.3


## Shoutouts & References
- [Flask](http://flask.pocoo.org/)
- [Werkzeug](http://werkzeug.pocoo.org/)
- [SQLAlchemy](http://www.sqlalchemy.org/)