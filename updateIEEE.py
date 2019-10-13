
import re
import sqlite3
from sqlite3 import Error

conn = sqlite3.connect('ieee.db')
c = conn.cursor()

def create_organization(mac, organization):
    sql = ''' INSERT INTO ieee(mac, organization)
              VALUES(?, ?) '''
    data = (mac, organization)
    c.execute(sql, data)
    conn.commit()
    return c.lastrowid

ieee = ''

with open('oui.txt', encoding='UTF-8') as file:
    for line in file:
        ieee += line

datas = re.findall(r'([\dABCDEF]{2}(\-[\dABCDEF]{2}){2}[^\n]+)', ieee)

for data in datas:
    preData = re.split('\s+', data[0])
    mac = preData[0]
    organization = ' '.join(preData[2:])
    print('{} {}'.format(mac, organization))
    create_organization(mac, organization)

print('Added {} mac-organizations'.format(len(datas)))