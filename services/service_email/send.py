import smtplib
from email.mime.text import MIMEText
from fastapi.exceptions import HTTPException
from fastapi import status


import configparser

config = configparser.ConfigParser()

config.read('../app/core/config.ini')

subject = "Confirm Registration"

sender = "niddleproject@gmail.com"


def send_email(mail_subject, body, sender_mail, recipient, password):
    msg = MIMEText(body)
    msg['Subject'] = mail_subject
    msg['From'] = sender_mail
    msg['To'] = recipient
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
            smtp_server.login(sender_mail, password)
            smtp_server.sendmail(sender_mail, recipient, msg.as_string())
        print("Message send!")
    except Exception as Error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Email sending error\n"
                   f"ERR: {Error}"
        )


def registration_mail(email):
    URL = f"http://127.0.0.1:8000/auth/mail_verification"

    return f"""Dear user,
            Thank you for creating your account.
            Please confirm your email address. The confirmation code is:
            \n
            {URL}/{email}
            \n
            If you have not requested a verification code, you can safely ignore this email․
    """


def registration_verify(email):
    send_email(subject, registration_mail(email), sender, email, config['API']['mailPass'])
