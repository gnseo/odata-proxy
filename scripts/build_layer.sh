rm -f layer.zip
rm -rf python
pipenv lock -r | sed 's/-e //g' | pipenv run pip install --upgrade -r /dev/stdin --target python
zip -r layer.zip python
rm -rf python
