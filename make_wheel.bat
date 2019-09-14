C:\Python27-32\Scripts\pip.exe install virtualenv
C:\Python27-32\Scripts\virtualenv venv27-32
venv27-32\Scripts\pip install wheel
venv27-32\Scripts\pip install cython
venv27-32\Scripts\python setup.py bdist_wheel
if %errorlevel% neq 0 exit /b %errorlevel%

C:\Python27\Scripts\pip.exe install virtualenv
C:\Python27\Scripts\virtualenv venv27
venv27\Scripts\pip install wheel
venv27\Scripts\pip install cython
venv27\Scripts\python setup.py bdist_wheel
if %errorlevel% neq 0 exit /b %errorlevel%

C:\Python35-32\python -m venv venv35-32
venv35-32\Scripts\pip install wheel
venv35-32\Scripts\pip install cython
venv35-32\Scripts\python setup.py bdist_wheel
if %errorlevel% neq 0 exit /b %errorlevel%

C:\Python35\python -m venv venv35
venv35\Scripts\pip install wheel
venv35\Scripts\pip install cython
venv35\Scripts\python setup.py bdist_wheel
if %errorlevel% neq 0 exit /b %errorlevel%

C:\Python36-32\python -m venv venv36-32
venv36-32\Scripts\pip install wheel
venv36-32\Scripts\pip install cython
venv36-32\Scripts\python setup.py bdist_wheel
if %errorlevel% neq 0 exit /b %errorlevel%

C:\Python36\python -m venv venv36
venv36\Scripts\pip install wheel
venv36\Scripts\pip install cython
venv36\Scripts\python setup.py bdist_wheel
if %errorlevel% neq 0 exit /b %errorlevel%

C:\Python37-32\python -m venv venv37-32
venv37-32\Scripts\pip install wheel
venv37-32\Scripts\pip install cython
venv37-32\Scripts\python setup.py bdist_wheel
if %errorlevel% neq 0 exit /b %errorlevel%

C:\Python37\python -m venv venv37
venv37\Scripts\pip install wheel
venv37\Scripts\pip install cython
venv37\Scripts\python setup.py bdist_wheel
if %errorlevel% neq 0 exit /b %errorlevel%
