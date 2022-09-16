---
permalink: /misc/python-email
title: Sending emails using python
---

<br>


The Simple Mail Transfer Protocol (SMTP) is an internet standard communication protocol for sending emails. <br>

Here is a script to send emails using Outlook's SMTP and python's smtplib library.

```py
import os
import smtplib
from email import encoders
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart

SENDER = 'from@outlook.com'
PASSWORD = 'XXXXXXXX'
RECEIVER = 'to@example.com'

msg = MIMEMultipart('Test message')
msg['Subject'] = 'Test subject'
msg['From'] = SENDER
msg['To'] = RECEIVER

attachments = ['file1.txt', 'file2.txt']
if len(attachments) > 0: 
    for f in attachments:
        part = MIMEBase('application', "octet-stream")
        part.set_payload( open(f,"rb").read() )
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="%s"' % os.path.basename(f))
        msg.attach(part)

server = smtplib.SMTP('smtp-mail.outlook.com', 587)
server.ehlo()
server.starttls()
server.login(SENDER, PASSWORD) 
server.sendmail(SENDER, RECEIVER, msg.as_string())
```
