# Dropperino
[![CodeFactor](https://www.codefactor.io/repository/github/krystianbajno/dropperino/badge)](https://www.codefactor.io/repository/github/krystianbajno/dropperino)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/b1efb74e463342cc942dcb34c4147627)](https://app.codacy.com/gh/krystianbajno/dropperino/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)

```
➜  dropperino git:(main) python3 dropperino.py 443 0.0.0.0 --ssl
+ Cert: /var/folders/p9/rrk794j13mg_pfg4zwbzz7h00000gn/T/tmp7o87ti78
+ Key: /var/folders/p9/rrk794j13mg_pfg4zwbzz7h00000gn/T/tmpbs6mwxu8
Starting HTTPS server on https://0.0.0.0:443
```

Simple upload/download file transfer server with SSL generation support.

Certificate generation requires `cryptography` package, but the code will run plain HTTP server without it.

# Installation
```bash
wget https://raw.githubusercontent.com/krystianbajno/dropperino/refs/heads/main/dropperino.py

pip install cryptography # optional for HTTPS
```

# Usage 
```bash
python3 dropperino.py -h # print help
python3 dropperino.py # 0.0.0.0 8000 http
python3 dropperino.py --ssl # https
python3 dropperino.py 8000 # port 
python3 dropperino.py 8000 0.0.0.0  # host port
python3 dropperino.py 8000 0.0.0.0 --ssl # host port https
python3 dropperino.py --dir /etc # 0.0.0.0 8000 http, serve /etc directory
python3 dropperino.py --dir --fullpath # Show full paths instead of relative paths

```
