import boto3
def send_email():
    client = boto3.client('ses')
    response = client.send_email(
        Destination={
            'BccAddresses': [
            ],
            'CcAddresses': [
            ],
            'ToAddresses': [
                'rmodi10@gmail.com',
            ],
        },
        Message={
            'Body': {
                'Html': {
                    'Charset': 'UTF-8',
                    'Data': 'Hi Admin, This is to inform that New commmunity has been created by the User<> and Name of the community .',
                },
                'Text': {
                    'Charset': 'UTF-8',
                    'Data': 'This is the message body in text format.',
                },
            },
            'Subject': {
                'Charset': 'UTF-8',
                'Data': 'Test email',
            },
        },
        Source='rmodi3191@gmail.com',
    )

def sendMessage():
    client = boto3.client('sns')
    number = '+15105857576'
    client.publish(PhoneNumber = number, Message='example text message' )