.PHONY: build dist docs
VERSION=`python setup.py -V`

WHL_FILES := $(wildcard dist/*.whl)
WHL_ASC := $(WHL_FILES:=.asc)
DIST_FILE := $(wildcard dist/*.tar.gz)
DIST_ASC := $(DIST_FILE:=.asc)

build:
	python setup.py build

dist:
	python setup.py sdist

install: dist
	pip -V
	pip install --no-cache-dir --no-deps --upgrade --force-reinstall --find-links ./dist/btdht-${VERSION}.tar.gz btdht

uninstall:
	pip uninstall btdht || true


dist/%.asc:
	gpg --detach-sign -a $(@:.asc=)

publish_pypi_release: test_venv test_venv/bin/twine dist sign_release
	test_venv/bin/twine upload --sign dist/*

sign_release: $(WHL_ASC) $(DIST_ASC)

test_venv/bin/twine:
	test_venv/bin/pip install twine

test_venv: test_venv/bin/python

test_venv/bin/python:
	virtualenv test_venv
	test_venv/bin/pip install -U --requirement requirements-dev.txt

test_venv/bin/sphinx-build: test_venv
	test_venv/bin/pip install Sphinx sphinx_rtd_theme

docs: test_venv/bin/sphinx-build
	bash -c "source test_venv/bin/activate; cd docs; make html"

clean:
	rm -rf build dist btdht.egg-info
	find ./btdht/ -name '*.c' -delete
	find ./ -name '*.pyc' -delete
	find ./ -name '*~' -delete

clean_docs:
	cd docs; make clean

clean_test_venv:
	rm -rf test_venv

clean_all: clean clean_test_venv clean_docs
