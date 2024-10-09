# Dropperino
```
➜  dropperino git:(main) python3 dropperino.py 0.0.0.0 443 --ssl
+ Cert: /var/folders/p9/rrk794j13mg_pfg4zwbzz7h00000gn/T/tmp7o87ti78
+ Key: /var/folders/p9/rrk794j13mg_pfg4zwbzz7h00000gn/T/tmpbs6mwxu8
Starting HTTPS server on https://0.0.0.0:443
```

Simple upload/download file transfer server with SSL support.

# Installation
```bash
wget https://raw.githubusercontent.com/krystianbajno/dropperino/refs/heads/main/dropperino.py
```

# Usage 
```bash
python3 dropperino.py # 0.0.0.0 8000 http
python3 dropperino.py --ssl # https
python3 dropperino.py 8000 # port 
python3 dropperino.py 0.0.0.0 8000 # host port
python3 dropperino.py 0.0.0.0 8000 --ssl # host port https
```