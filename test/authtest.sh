auth=`echo -n "bob:bobspassword" | base64`
curl -b cookies.txt \
     -c cookies.txt \
     -H "Authorization: basic $auth" \
     http://localhost/auth?login
vars -vn session/info
curl -b cookies.txt \
     -c cookies.txt \
     http://localhost/auth?logout
vars -vn session/info



