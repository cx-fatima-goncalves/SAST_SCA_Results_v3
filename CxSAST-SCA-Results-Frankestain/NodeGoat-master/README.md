# Server API

### Scripts
```sh
# start develop mode
npm run start:dev
```

<br>

### Add `admin` on database

Add and admin user on database. Please restore the password to receive a new one:
```sh
use torterradb
db.users.insert({name: "admin", email: "admin@admin.com", role: 2})
```
