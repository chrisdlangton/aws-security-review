from libs import Database
from json import dumps

db = Database()
for key in db.getall():
    print("""
### {key}
{json}
""".format(key=key, json=dumps(db.get(key), indent=2, sort_keys=True))
)
