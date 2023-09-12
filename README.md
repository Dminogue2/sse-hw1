Usage:
	python3 main.py [mode] [filepath]
	-[mode]:
		"detectOnly": Uses existing database to search for cvp's and cve's related to dependencies found in [filepath]
		"doAll": Same as detectOnly, but first destroys and recreates existing database using API calls.
			Depending on network avalibility this may take a few minutes. In testing ~5 minutes on the long end.
	-[filepath]:
		Path to a 'POM' file which will be analysed
	
	-If NVD-SQL.sqlite is downloaded, then both modes can be chosen for operation. Otherwise, "doAll" is needed to regenerate database.