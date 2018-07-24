# NVD-Playset
Some simple tools for playing with NIST's NVD data feeds

## Using the playset

1. Download files from NIST
  Run the script(s):
  
  '''shell
  $ python downloadNVD_JSON.py
  '''
  
  or
  
  ```shell
  $ python downloadNVD_XML.py
  ```
  
  This will create a folder 'nvd', where the JSON and/or XML files will be downloaded to.
  
2. Build a Python Dict
...Run the script:
  
...```shell
...$ python JSONtoDict.py
...```
  
...This will create a dict with the NVD entries for each year. 
...This makes getting started with some Python scripting nice and easy.
  
3. Build a Database
...Sometimes a DB is needed. This gets that done.
...NOTE: You must run the Dict script first. We use the pickled dict to build the DB.
  
...Run the following:
...```shell
...$ python dictToDB.py
...```
...Now you will have a nice new DB (nvd.db).
  
4. Time to play!
