```python
import requests
from time import sleep
from selenium import webdriver
from tqdm import tqdm
s = requests.Session()

def get_sol_upvotes(user):
    url = f"https://cryptohack.org/user/{user}/"
    sol_upvotes = s.get(url).text.split("Solution Upvotes")[1][6:].split("<")[0]
    return int(sol_upvotes)

dic = {}
for p in tqdm(range(1, 201)):
    driver = webdriver.Firefox()
    driver.get("https://cryptohack.org/scoreboard/")
    js = f'openPage({p}, "any")'
    driver.execute_script(js)
    sleep(5)
    html = driver.execute_script("return document.getElementsByTagName('html')[0].innerHTML")
    for i, line in enumerate(html.split('name"><a href="/user/')):
        if i > 10:
            user = line.split('">')[0]
            upvotes = get_sol_upvotes(user)
            if upvotes > 10:
                dic[user] = upvotes
    driver.close()
           
for i, (user, upvotes) in enumerate({ key: value for key, value in sorted(dic.items(), key=lambda item: item[1])[::-1] }.items()):
    print(f"{i+1}.", upvotes, user)
```
