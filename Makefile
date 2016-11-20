.PHONY: build dist docs
VERSION=`python setup.py -V`

build:
	python setup.py build

dist:
	python setup.py sdist

install: dist
	pip -V
	pip install --no-cache-dir --no-deps --upgrade --force-reinstall --find-links ./dist/btdht-${VERSION}.tar.gz btdht

uninstall:
	pip uninstall btdht || true


clean:
	rm -rf build dist btdht.egg-info
	find ./btdht/ -name '*.c' -delete
	find ./ -name '*~' -delete

publish_pypi_release:
	python setup.py sdist upload --sign

